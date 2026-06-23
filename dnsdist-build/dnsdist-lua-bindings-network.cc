/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-lua-network.hh"
#include "dolog.hh"

/* --- resolveViaDoH: 纯 IP DoH 自举解析器 ---
 * 在 dnsdist.conf 配置加载阶段使用，通过直连一个纯 IP 的 DoH 端点
 * 来解析上游 DNS 服务器的域名，避免明文 UDP DNS 泄漏。
 *
 * 用法:
 *   local ips = resolveViaDoH('doh.pub', 'https://223.5.5.5/dns-query')
 *   for _, ip in ipairs(ips) do
 *     newServer({ address = ip .. ':443', subjectName = 'doh.pub', ... })
 *   end
 */

#include <cstring>
#include <vector>

#ifdef HAVE_LIBSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include "dnsdist-dnsparser.hh"
#include "dnsdist-random.hh"
#include "dnswriter.hh"

#ifdef HAVE_LIBSSL

namespace {

struct DohBootstrapUrl
{
  std::string host;
  uint16_t port{443};
  std::string path{"dns-query"};
};

static DohBootstrapUrl parseDohUrl(const std::string& url)
{
  DohBootstrapUrl result;
  std::string s = url;

  // strip https:// prefix
  if (s.size() > 8 && s.substr(0, 8) == "https://") {
    s = s.substr(8);
  }

  // split path
  auto slash = s.find('/');
  if (slash != std::string::npos) {
    result.path = s.substr(slash + 1);
    s = s.substr(0, slash);
  }

  // split host:port
  auto colon = s.find(':');
  if (colon != std::string::npos) {
    result.host = s.substr(0, colon);
    result.port = static_cast<uint16_t>(std::stoul(s.substr(colon + 1)));
  }
  else {
    result.host = s;
  }

  return result;
}

static PacketBuffer makeDnsQueryPacket(const DNSName& name, uint16_t qtype)
{
  PacketBuffer packet;
  GenericDNSPacketWriter<PacketBuffer> pw(packet, name, qtype);
  pw.commit();
  auto* dh = reinterpret_cast<dnsheader*>(packet.data());
  dh->rd = 1;
  dh->id = htons(dnsdist::getRandomDNSID());
  return packet;
}

static std::vector<std::string> doDohLookup(const std::string& name, uint16_t qtype,
    const std::string& host, uint16_t port, const std::string& path, int timeoutMs)
{
  std::vector<std::string> result;

  // 1. build DNS query packet
  DNSName dnsName(name);
  auto query = makeDnsQueryPacket(dnsName, qtype);

  // 2. TCP socket
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    warnlog("resolveViaDoH: socket() failed for %s", host);
    return result;
  }

  // set connect/read/write timeout
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

  // 3. connect to bootstrap resolver (raw IP, no DNS needed)
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
    warnlog("resolveViaDoH: bootstrap address '%s' is not a valid IPv4 address", host);
    close(sock);
    return result;
  }

  if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
    warnlog("resolveViaDoH: connect() to %s:%d failed: %s", host, port, strerror(errno));
    close(sock);
    return result;
  }

  // 4. TLS handshake (verify none — bootstrap resolver is trusted by IP)
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == nullptr) {
    close(sock);
    return result;
  }
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

  SSL* ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    SSL_CTX_free(ctx);
    close(sock);
    return result;
  }
  SSL_set_fd(ssl, sock);

  if (SSL_connect(ssl) != 1) {
    unsigned long err = ERR_get_error();
    warnlog("resolveViaDoH: TLS handshake to %s:%d failed: %s", host, port, err != 0 ? ERR_error_string(err, nullptr) : "unknown");
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return result;
  }

  // 5. HTTP/1.1 POST with application/dns-message wire format
  std::string body(reinterpret_cast<const char*>(query.data()), query.size());
  std::string httpRequest =
    "POST /" + path + " HTTP/1.1\r\n"
    "Host: " + host + "\r\n"
    "Content-Type: application/dns-message\r\n"
    "Accept: application/dns-message\r\n"
    "Content-Length: " + std::to_string(body.size()) + "\r\n"
    "Connection: close\r\n"
    "\r\n" + body;

  if (SSL_write(ssl, httpRequest.data(), httpRequest.size()) <= 0) {
    warnlog("resolveViaDoH: SSL_write() to %s failed", host);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sock);
    return result;
  }

  // 6. read HTTP response (Connection: close, just read until EOF)
  std::string httpResponse;
  char buf[65536];
  int n;
  while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
    httpResponse.append(buf, static_cast<size_t>(n));
  }

  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(sock);

  if (httpResponse.empty()) {
    return result;
  }

  // 7. strip HTTP headers, locate body
  auto headerEnd = httpResponse.find("\r\n\r\n");
  if (headerEnd == std::string::npos) {
    warnlog("resolveViaDoH: invalid HTTP response from %s (no header terminator)", host);
    return result;
  }

  const char* dnsData = httpResponse.data() + headerEnd + 4;
  size_t dnsLen = httpResponse.size() - headerEnd - 4;

  if (dnsLen < sizeof(dnsheader)) {
    warnlog("resolveViaDoH: DNS response too short from %s (%zu bytes)", host, dnsLen);
    return result;
  }

  // 8. parse DNS response, extract A/AAAA addresses
  try {
    dnsdist::DNSPacketOverlay overlay(std::string_view(dnsData, dnsLen));
    for (const auto& record : overlay.d_records) {
      if (record.d_place != DNSResourceRecord::ANSWER) {
        continue;
      }
      auto addr = dnsdist::RecordParsers::parseAddressRecord(std::string_view(dnsData, dnsLen), record);
      if (addr) {
        result.push_back(addr->toString());
      }
    }
  }
  catch (const std::exception& e) {
    warnlog("resolveViaDoH: failed to parse DNS response for %s via %s: %s", name, host, e.what());
  }

  return result;
}

} // anonymous namespace
#endif /* HAVE_LIBSSL */

void setupLuaBindingsNetwork(LuaContext& luaCtx, bool client, bool configCheck)
{
  luaCtx.writeFunction("newNetworkEndpoint", [client](const std::string& path) {
    if (client) {
      return std::shared_ptr<dnsdist::NetworkEndpoint>(nullptr);
    }

    try {
      return std::make_shared<dnsdist::NetworkEndpoint>(path);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("Error connecting to network endpoint: %s", e.what()),
           dnsdist::logging::getTopLogger("newNetworkEndpoint")->error(Logr::Error, e.what(), "Error connecting to network endpoint"));
    }
    return std::shared_ptr<dnsdist::NetworkEndpoint>(nullptr);
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkEndpoint>::*)() const>("isValid", [](const std::shared_ptr<dnsdist::NetworkEndpoint>& endpoint) {
    return endpoint != nullptr;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkEndpoint>::*)(const std::string&) const>("send", [client](const std::shared_ptr<dnsdist::NetworkEndpoint>& endpoint, const std::string& payload) {
    if (client || !endpoint || payload.empty()) {
      return false;
    }

    return endpoint->send(payload);
  });

  luaCtx.writeFunction("newNetworkListener", [client]() {
    if (client) {
      return std::shared_ptr<dnsdist::NetworkListener>(nullptr);
    }

    return std::make_shared<dnsdist::NetworkListener>();
  });

  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkListener>::*)(const std::string&, uint16_t, std::function<void(uint16_t, std::string& dgram, const std::string& from)>)>("addUnixListeningEndpoint", [client](std::shared_ptr<dnsdist::NetworkListener>& listener, const std::string& path, uint16_t endpointID, std::function<void(uint16_t endpoint, std::string& dgram, const std::string& from)> cb) {
    if (client || !cb) {
      return false;
    }

    return listener->addUnixListeningEndpoint(path, endpointID, [cb = std::move(cb)](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      {
        auto lock = g_lua.lock();
        cb(endpoint, dgram, from);
      }
      dnsdist::handleQueuedAsynchronousEvents();
    });
  });

  // if you make the dnsdist_ffi_network_message_t* in the function prototype const, LuaWrapper will stop treating it like a lightuserdata, messing everything up!!
  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::NetworkListener>::*)(const std::string&, uint16_t, std::function<void(dnsdist_ffi_network_message_t*)>)>("addUnixListeningEndpointFFI", [client](std::shared_ptr<dnsdist::NetworkListener>& listener, const std::string& path, uint16_t endpointID, std::function<void(dnsdist_ffi_network_message_t*)> cb) {
    if (client) {
      return false;
    }

    return listener->addUnixListeningEndpoint(path, endpointID, [cb = std::move(cb)](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      {
        auto lock = g_lua.lock();
        dnsdist_ffi_network_message_t msg(dgram, from, endpoint);
        cb(&msg);
      }
      dnsdist::handleQueuedAsynchronousEvents();
    });
  });

  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::NetworkListener>::*)()>("start", [client, configCheck](std::shared_ptr<dnsdist::NetworkListener>& listener) {
    if (client || configCheck) {
      return;
    }

    listener->start();
  });

  luaCtx.writeFunction("getResolvers", [](const std::string& resolvConfPath) -> LuaArray<std::string> {
    auto resolvers = getResolvers(resolvConfPath);
    LuaArray<std::string> result;
    result.reserve(resolvers.size());
    int counter = 1;
    for (const auto& resolver : resolvers) {
      result.emplace_back(counter, resolver.toString());
      counter++;
    }
    return result;
  });

#ifdef HAVE_LIBSSL
  auto normalizeEndpoints = [](const std::string& name, const boost::variant<std::string, LuaArray<std::string>>& urls) {
    struct EP { std::string host; uint16_t port{443}; std::string path{"dns-query"}; };
    std::vector<EP> eps;
    std::vector<std::string> urlList;

    if (urls.type() == typeid(std::string)) {
      urlList.push_back(boost::get<std::string>(urls));
    }
    else {
      for (const auto& pair : boost::get<LuaArray<std::string>>(urls)) {
        if (!pair.second.empty()) urlList.push_back(pair.second);
      }
    }

    for (const auto& u : urlList) {
      auto parsed = parseDohUrl(u);
      struct sockaddr_in sa;
      memset(&sa, 0, sizeof(sa));
      if (inet_pton(AF_INET, parsed.host.c_str(), &(sa.sin_addr)) != 1) {
        warnlog("resolveViaDoH: '%s' is not a raw IPv4 — skipping", parsed.host);
        continue;
      }
      eps.push_back({std::move(parsed.host), parsed.port, std::move(parsed.path)});
    }

    if (eps.empty()) {
      warnlog("resolveViaDoH: no valid bootstrap endpoints for '%s'", name);
      return eps;
    }

    // Fisher-Yates shuffle — 避免单点故障
    for (size_t i = eps.size(); i > 1; --i) {
      std::swap(eps[i - 1], eps[dnsdist::getRandomValue(i)]);
    }
    return eps;
  };

  /* --- resolveViaDoH: 多端点 DoH bootstrap 解析 ---
   * 参数:
   *   name     — 要解析的域名 (如 "doh.pub")
   *   urls     — DoH 端点，单个 URL 或 URL 数组
   *              如 'https://223.5.5.5/dns-query'
   *              或 {'https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query'}
   *   timeoutMs— 超时毫秒 (可选, 默认 5000)
   * 返回:
   *   IP 字符串数组 (IPv4 在前 IPv6 在后)，所有端点均失败时返回空表
   */
  luaCtx.writeFunction("resolveViaDoH", [client, normalizeEndpoints](const std::string& name, const boost::variant<std::string, LuaArray<std::string>>& urls, std::optional<uint64_t> timeoutMs) -> LuaArray<std::string> {
    LuaArray<std::string> result;
    if (client) return result;

    auto eps = normalizeEndpoints(name, urls);
    if (eps.empty()) return result;

    int timeout = timeoutMs ? static_cast<int>(*timeoutMs) : 5000;
    std::string usedHost;

    for (const auto& ep : eps) {
      auto v4 = doDohLookup(name, QType::A, ep.host, ep.port, ep.path, timeout);
      auto v6 = doDohLookup(name, QType::AAAA, ep.host, ep.port, ep.path, timeout);
      if (!v4.empty() || !v6.empty()) {
        usedHost = ep.host;
        int counter = 1;
        for (const auto& ip : v4) result.emplace_back(counter++, ip);
        for (const auto& ip : v6) result.emplace_back(counter++, ip);
        break;
      }
    }

    if (result.empty()) {
      warnlog("resolveViaDoH: all %zu bootstrap endpoints failed for '%s'", eps.size(), name);
    }
    else {
      infolog("resolveViaDoH: resolved '%s' via %s -> %zu address(es)", name, usedHost, result.size());
    }
    return result;
  });

  /* --- resolveViaDoHFirst: 返回第一个 IP 字符串 ---
   * 便捷版，适用于"只建一个 server"场景。
   */
  luaCtx.writeFunction("resolveViaDoHFirst", [client, normalizeEndpoints](const std::string& name, const boost::variant<std::string, LuaArray<std::string>>& urls, std::optional<uint64_t> timeoutMs) -> std::string {
    if (client) return {};

    auto eps = normalizeEndpoints(name, urls);
    if (eps.empty()) return {};

    int timeout = timeoutMs ? static_cast<int>(*timeoutMs) : 5000;

    for (const auto& ep : eps) {
      auto v4 = doDohLookup(name, QType::A, ep.host, ep.port, ep.path, timeout);
      if (!v4.empty()) {
        infolog("resolveViaDoHFirst: resolved '%s' -> %s", name, v4.at(0));
        return v4.at(0);
      }
      auto v6 = doDohLookup(name, QType::AAAA, ep.host, ep.port, ep.path, timeout);
      if (!v6.empty()) {
        infolog("resolveViaDoHFirst: resolved '%s' -> %s (AAAA)", name, v6.at(0));
        return v6.at(0);
      }
    }

    warnlog("resolveViaDoHFirst: all %zu bootstrap endpoints failed for '%s'", eps.size(), name);
    return {};
  });
#endif /* HAVE_LIBSSL */
};
