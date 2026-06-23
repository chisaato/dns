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
#include <cinttypes>
#include <fcntl.h>
#include <unistd.h>

#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-ecs.hh"
#include "ednssubnet.hh"
#include "packetcache.hh"
#include "base64.hh"

DNSDistPacketCache::DNSDistPacketCache(CacheSettings settings) :
  d_settings(std::move(settings))
{
  if (d_settings.d_maxEntries == 0) {
    throw std::runtime_error("Trying to create a 0-sized packet-cache");
  }

  if (d_settings.d_shardCount == 0) {
    d_settings.d_shardCount = 1;
  }

  d_shards.resize(d_settings.d_shardCount);

  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  for (auto& shard : d_shards) {
    shard.setSize((d_settings.d_maxEntries / d_settings.d_shardCount) + 1);
  }
}

bool DNSDistPacketCache::getClientSubnet(const PacketBuffer& packet, size_t qnameWireLength, std::optional<Netmask>& subnet)
{
  uint16_t optRDPosition = 0;
  size_t remaining = 0;

  int res = dnsdist::getEDNSOptionsStart(packet, qnameWireLength, &optRDPosition, &remaining);

  if (res == 0) {
    size_t ecsOptionStartPosition = 0;
    size_t ecsOptionSize = 0;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    res = getEDNSOption(reinterpret_cast<const char*>(&packet.at(optRDPosition)), remaining, EDNSOptionCode::ECS, &ecsOptionStartPosition, &ecsOptionSize);

    if (res == 0 && ecsOptionSize > (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {

      EDNSSubnetOpts eso;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      if (EDNSSubnetOpts::getFromString(reinterpret_cast<const char*>(&packet.at(optRDPosition + ecsOptionStartPosition + (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))), ecsOptionSize - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), &eso)) {
        subnet = eso.getSource();
        return true;
      }
    }
  }

  return false;
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet) const
{
  if (cachedValue.queryFlags != queryFlags || cachedValue.dnssecOK != dnssecOK || cachedValue.receivedOverUDP != receivedOverUDP || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname) {
    return false;
  }

  if (d_settings.d_parseECS && cachedValue.subnet != subnet) {
    return false;
  }

  return true;
}

bool DNSDistPacketCache::insertLocked(std::unordered_map<uint32_t, CacheValue>& map, uint32_t key, CacheValue& newValue)
{
  /* check again now that we hold the lock to prevent a race */
  if (map.size() >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
    return false;
  }

  std::unordered_map<uint32_t, CacheValue>::iterator mapIt;
  bool result{false};
  std::tie(mapIt, result) = map.insert({key, newValue});

  if (result) {
    return true;
  }

  /* in case of collision, don't override the existing entry
     except if it has expired */
  CacheValue& value = mapIt->second;
  bool wasExpired = value.validity <= newValue.added;

  if (!wasExpired && !cachedValueMatches(value, newValue.queryFlags, newValue.qname, newValue.qtype, newValue.qclass, newValue.receivedOverUDP, newValue.dnssecOK, newValue.subnet)) {
    ++d_insertCollisions;
    return false;
  }

  /* if the existing entry had a longer TTD, keep it */
  if (newValue.validity <= value.validity) {
    return false;
  }

  value = newValue;
  return false;
}

void DNSDistPacketCache::insert(uint32_t key, const std::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, std::optional<uint32_t> tempFailureTTL)
{
  if (response.size() < sizeof(dnsheader) || response.size() > getMaximumEntrySize()) {
    return;
  }

  if (qtype == QType::AXFR || qtype == QType::IXFR) {
    return;
  }

  uint32_t minTTL{0};

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = tempFailureTTL == std::nullopt ? d_settings.d_tempFailureTTL : *tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    bool seenAuthSOA = false;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    minTTL = getMinTTL(reinterpret_cast<const char*>(response.data()), response.size(), &seenAuthSOA);

    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      /* no TTL found, we probably don't want to cache this
         unless it's an empty (no records) truncated answer,
         and we have been asked to cache these */
      if (d_settings.d_truncatedTTL == 0) {
        return;
      }
      dnsheader_aligned dh_aligned(response.data());
      if (dh_aligned->tc == 0) {
        return;
      }
      minTTL = d_settings.d_truncatedTTL;
    }

    if (rcode == RCode::NXDomain || (rcode == RCode::NoError && seenAuthSOA)) {
      minTTL = std::min(minTTL, d_settings.d_maxNegativeTTL);
    }
    else if (minTTL > d_settings.d_maxTTL) {
      minTTL = d_settings.d_maxTTL;
    }

    if (minTTL < d_settings.d_minTTL) {
      ++d_ttlTooShorts;
      return;
    }
  }

  uint32_t shardIndex = getShardIndex(key);

  if (d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
    return;
  }

  const time_t now = time(nullptr);
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.queryFlags = queryFlags;
  newValue.len = response.size();
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.receivedOverUDP = receivedOverUDP;
  newValue.dnssecOK = dnssecOK;
  newValue.value = std::string(response.begin(), response.end());
  newValue.subnet = subnet;

  auto& shard = d_shards.at(shardIndex);

  bool inserted = false;
  if (d_settings.d_deferrableInsertLock) {
    auto lock = shard.d_map.try_write_lock();

    if (!lock.owns_lock()) {
      ++d_deferredInserts;
      return;
    }
    inserted = insertLocked(*lock, key, newValue);
  }
  else {
    auto lock = shard.d_map.write_lock();

    inserted = insertLocked(*lock, key, newValue);
  }
  if (inserted) {
    ++shard.d_entriesCount;
    d_dirty.store(true);
  }
}

bool DNSDistPacketCache::get(DNSQuestion& dnsQuestion, uint16_t queryId, uint32_t* keyOut, std::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired, bool skipAging, bool truncatedOK, bool recordMiss)
{
  if (dnsQuestion.ids.qtype == QType::AXFR || dnsQuestion.ids.qtype == QType::IXFR) {
    ++d_misses;
    return false;
  }

  const auto& dnsQName = dnsQuestion.ids.qname.getStorage();
  uint32_t key = getKey(dnsQName, dnsQuestion.ids.qname.wirelength(), dnsQuestion.getData(), receivedOverUDP);

  if (keyOut != nullptr) {
    *keyOut = key;
  }

  if (d_settings.d_parseECS) {
    getClientSubnet(dnsQuestion.getData(), dnsQuestion.ids.qname.wirelength(), subnet);
  }

  uint32_t shardIndex = getShardIndex(key);
  time_t now = time(nullptr);
  time_t age{0};
  bool stale = false;
  auto& response = dnsQuestion.getMutableData();
  auto& shard = d_shards.at(shardIndex);
  {
    auto map = shard.d_map.try_read_lock();
    if (!map.owns_lock()) {
      ++d_deferredLookups;
      return false;
    }

    auto mapIt = map->find(key);
    if (mapIt == map->end()) {
      if (recordMiss) {
        ++d_misses;
      }
      return false;
    }

    const CacheValue& value = mapIt->second;
    if (value.validity <= now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        if (recordMiss) {
          ++d_misses;
        }
        return false;
      }
      stale = true;
    }

    if (value.len < sizeof(dnsheader)) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnsQuestion.ids.qname, dnsQuestion.ids.qtype, dnsQuestion.ids.qclass, receivedOverUDP, dnssecOK, subnet)) {
      ++d_lookupCollisions;
      return false;
    }

    if (!truncatedOK) {
      dnsheader_aligned dh_aligned(value.value.data());
      if (dh_aligned->tc != 0) {
        return false;
      }
    }

    response.resize(value.len);
    memcpy(&response.at(0), &queryId, sizeof(queryId));
    memcpy(&response.at(sizeof(queryId)), &value.value.at(sizeof(queryId)), sizeof(dnsheader) - sizeof(queryId));

    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      ++d_hits;
      return true;
    }

    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(&response.at(sizeof(dnsheader)), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(&response.at(sizeof(dnsheader) + dnsQNameLen), &value.value.at(sizeof(dnsheader) + dnsQNameLen), value.len - (sizeof(dnsheader) + dnsQNameLen));
    }

    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_settings.d_staleTTL;
      dnsQuestion.ids.staleCacheHit = true;
    }
  }

  if (!d_settings.d_dontAge && !skipAging) {
    if (!stale) {
      // coverity[store_truncates_time_t]
      dnsheader_aligned dh_aligned(response.data());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      ageDNSPacket(reinterpret_cast<char*>(response.data()), response.size(), age, dh_aligned);
    }
    else {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      editDNSPacketTTL(reinterpret_cast<char*>(response.data()), response.size(),
                       [staleTTL = d_settings.d_staleTTL](uint8_t /* section */, uint16_t /* class_ */, uint16_t /* type */, uint32_t /* ttl */) { return staleTTL; });
    }
  }

  if (d_settings.d_shuffle) {
    dnsheader_aligned dh_aligned(response.data());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    shuffleDNSPacket(reinterpret_cast<char*>(response.data()), response.size(), dh_aligned);
  }

  ++d_hits;
  return true;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::purgeExpired(size_t upTo, const time_t now)
{
  const size_t maxPerShard = upTo / d_settings.d_shardCount;

  size_t removed = 0;

  ++d_cleanupCount;
  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();
    if (map->size() <= maxPerShard) {
      continue;
    }

    size_t toRemove = map->size() - maxPerShard;

    for (auto it = map->begin(); toRemove > 0 && it != map->end();) {
      const CacheValue& value = it->second;

      if (value.validity <= now) {
        it = map->erase(it);
        --toRemove;
        --shard.d_entriesCount;
        ++removed;
      }
      else {
        ++it;
      }
    }
  }

  return removed;
}

/* Remove all entries, keeping only upTo
   entries in the cache.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::expunge(size_t upTo)
{
  const size_t maxPerShard = upTo / d_settings.d_shardCount;

  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();

    if (map->size() <= maxPerShard) {
      continue;
    }

    size_t toRemove = map->size() - maxPerShard;

    auto beginIt = map->begin();
    auto endIt = beginIt;

    if (map->size() >= toRemove) {
      std::advance(endIt, toRemove);
      map->erase(beginIt, endIt);
      shard.d_entriesCount -= toRemove;
      removed += toRemove;
    }
    else {
      removed += map->size();
      map->clear();
      shard.d_entriesCount = 0;
    }
  }

  return removed;
}

size_t DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();

    for (auto it = map->begin(); it != map->end();) {
      const CacheValue& value = it->second;

      if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
        it = map->erase(it);
        --shard.d_entriesCount;
        ++removed;
      }
      else {
        ++it;
      }
    }
  }

  return removed;
}

bool DNSDistPacketCache::isFull()
{
  return (getSize() >= d_settings.d_maxEntries);
}

uint64_t DNSDistPacketCache::getSize()
{
  uint64_t count = 0;

  for (auto& shard : d_shards) {
    count += shard.d_entriesCount;
  }

  return count;
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA)
{
  return getDNSPacketMinTTL(packet, length, seenNoDataSOA);
}

uint32_t DNSDistPacketCache::getKey(const DNSName::string_t& qname, size_t qnameWireLength, const PacketBuffer& packet, bool receivedOverUDP) const
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packet.size() < sizeof(dnsheader)) {
    throw std::range_error("Computing packet cache key for an invalid packet size (" + std::to_string(packet.size()) + ")");
  }

  result = burtle(&packet.at(2), sizeof(dnsheader) - 2, result);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  result = burtleCI(reinterpret_cast<const unsigned char*>(qname.c_str()), qname.length(), result);
  if (packet.size() < sizeof(dnsheader) + qnameWireLength) {
    throw std::range_error("Computing packet cache key for an invalid packet (" + std::to_string(packet.size()) + " < " + std::to_string(sizeof(dnsheader) + qnameWireLength) + ")");
  }
  if (packet.size() > ((sizeof(dnsheader) + qnameWireLength))) {
    if (!d_settings.d_optionsToSkip.empty() || !d_settings.d_payloadRanks.empty()) {
      /* skip EDNS options if any */
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      result = PacketCache::hashAfterQname(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()), result, sizeof(dnsheader) + qnameWireLength, d_settings.d_optionsToSkip, d_settings.d_payloadRanks);
    }
    else {
      result = burtle(&packet.at(sizeof(dnsheader) + qnameWireLength), packet.size() - (sizeof(dnsheader) + qnameWireLength), result);
    }
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  result = burtle(reinterpret_cast<const unsigned char*>(&receivedOverUDP), sizeof(receivedOverUDP), result);
  return result;
}

uint32_t DNSDistPacketCache::getShardIndex(uint32_t key) const
{
  return key % d_settings.d_shardCount;
}

string DNSDistPacketCache::toString()
{
  return std::to_string(getSize()) + "/" + std::to_string(d_settings.d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  return getSize();
}

uint64_t DNSDistPacketCache::dump(int fileDesc, bool rawResponse)
{
  auto fileDescDuplicated = dup(fileDesc);
  if (fileDescDuplicated < 0) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDescDuplicated, "w"));
  if (filePtr == nullptr) {
    return 0;
  }

  fprintf(filePtr.get(), "; dnsdist's packet cache dump follows\n;\n");

  uint64_t count = 0;
  time_t now = time(nullptr);
  for (auto& shard : d_shards) {
    auto map = shard.d_map.read_lock();

    for (const auto& entry : *map) {
      const CacheValue& value = entry.second;
      count++;

      try {
        uint8_t rcode = 0;
        if (value.len >= sizeof(dnsheader)) {
          dnsheader dnsHeader{};
          memcpy(&dnsHeader, value.value.data(), sizeof(dnsheader));
          rcode = dnsHeader.rcode;
        }

        fprintf(filePtr.get(), "%s %" PRId64 " %s %s ; ecs %s, rcode %" PRIu8 ", key %" PRIu32 ", length %" PRIu16 ", received over UDP %d, added %" PRId64 ", dnssecOK %d, raw query flags %" PRIu16, value.qname.toString().c_str(), static_cast<int64_t>(value.validity - now), QClass(value.qclass).toString().c_str(), QType(value.qtype).toString().c_str(), value.subnet ? value.subnet.value().toString().c_str() : "empty", rcode, entry.first, value.len, value.receivedOverUDP ? 1 : 0, static_cast<int64_t>(value.added), value.dnssecOK ? 1 : 0, value.queryFlags);

        if (rawResponse) {
          std::string rawDataResponse = Base64Encode(value.value);
          fprintf(filePtr.get(), ", base64response %s", rawDataResponse.c_str());
        }
        fprintf(filePtr.get(), "\n");
      }
      catch (...) {
        fprintf(filePtr.get(), "; error printing '%s'\n", value.qname.empty() ? "EMPTY" : value.qname.toString().c_str());
      }
    }
  }

  return count;
}

std::set<DNSName> DNSDistPacketCache::getDomainsContainingRecords(const ComboAddress& addr)
{
  std::set<DNSName> domains;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.read_lock();

    for (const auto& entry : *map) {
      const CacheValue& value = entry.second;

      try {
        if (value.len < sizeof(dnsheader)) {
          continue;
        }

        dnsheader_aligned dnsHeader(value.value.data());
        if (dnsHeader->rcode != RCode::NoError || (dnsHeader->ancount == 0 && dnsHeader->nscount == 0 && dnsHeader->arcount == 0)) {
          continue;
        }

        bool found = false;
        bool valid = visitDNSPacket(value.value, [addr, &found](uint8_t /* section */, uint16_t qclass, uint16_t qtype, uint32_t /* ttl */, uint16_t rdatalength, const char* rdata) {
          if (qtype == QType::A && qclass == QClass::IN && addr.isIPv4() && rdatalength == 4 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin4.sin_family = AF_INET;
            memcpy(&parsed.sin4.sin_addr.s_addr, rdata, rdatalength);
            if (parsed == addr) {
              found = true;
              return true;
            }
          }
          else if (qtype == QType::AAAA && qclass == QClass::IN && addr.isIPv6() && rdatalength == 16 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin6.sin6_family = AF_INET6;
            memcpy(&parsed.sin6.sin6_addr.s6_addr, rdata, rdatalength);
            if (parsed == addr) {
              found = true;
              return true;
            }
          }

          return false;
        });

        if (valid && found) {
          domains.insert(value.qname);
        }
      }
      catch (...) {
        continue;
      }
    }
  }

  return domains;
}

std::set<ComboAddress> DNSDistPacketCache::getRecordsForDomain(const DNSName& domain)
{
  std::set<ComboAddress> addresses;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.read_lock();

    for (const auto& entry : *map) {
      const CacheValue& value = entry.second;

      try {
        if (value.qname != domain) {
          continue;
        }

        if (value.len < sizeof(dnsheader)) {
          continue;
        }

        dnsheader_aligned dnsHeader(value.value.data());
        if (dnsHeader->rcode != RCode::NoError || (dnsHeader->ancount == 0 && dnsHeader->nscount == 0 && dnsHeader->arcount == 0)) {
          continue;
        }

        visitDNSPacket(value.value, [&addresses](uint8_t /* section */, uint16_t qclass, uint16_t qtype, uint32_t /* ttl */, uint16_t rdatalength, const char* rdata) {
          if (qtype == QType::A && qclass == QClass::IN && rdatalength == 4 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin4.sin_family = AF_INET;
            memcpy(&parsed.sin4.sin_addr.s_addr, rdata, rdatalength);
            addresses.insert(parsed);
          }
          else if (qtype == QType::AAAA && qclass == QClass::IN && rdatalength == 16 && rdata != nullptr) {
            ComboAddress parsed;
            parsed.sin6.sin6_family = AF_INET6;
            memcpy(&parsed.sin6.sin6_addr.s6_addr, rdata, rdatalength);
            addresses.insert(parsed);
          }

          return false;
        });
      }
      catch (...) {
        continue;
      }
    }
  }

  return addresses;
}

/* ===== Persistent cache: binary save/load ===== */

static constexpr char s_persistentCacheMagic[] = "DPC1";
static constexpr uint32_t s_persistentCacheVersion = 1;

bool DNSDistPacketCache::save(const std::string& path)
{
  std::string tmpPath = path + ".tmp";
  int fd = open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0660);
  if (fd < 0) {
    return false;
  }

  auto writeAll = [fd](const void* buf, size_t len) -> bool {
    const char* p = static_cast<const char*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
      ssize_t n = write(fd, p, remaining);
      if (n <= 0) return false;
      p += n;
      remaining -= static_cast<size_t>(n);
    }
    return true;
  };

  if (!writeAll(s_persistentCacheMagic, 4) || !writeAll(&s_persistentCacheVersion, sizeof(uint32_t))) {
    close(fd);
    unlink(tmpPath.c_str());
    return false;
  }

  uint32_t entryCount = 0;
  off_t countOffset = lseek(fd, 0, SEEK_CUR);
  writeAll(&entryCount, sizeof(entryCount));

  time_t now = time(nullptr);
  uint32_t writtenCount = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.read_lock();
    for (const auto& [key, value] : *map) {
      if (value.validity <= now) {
        continue;
      }

      bool ok = true;
      ok = ok && writeAll(&key, sizeof(key));
      const auto& storage = value.qname.getStorage();
      uint16_t qnameLen = static_cast<uint16_t>(storage.size());
      ok = ok && writeAll(&qnameLen, sizeof(qnameLen));
      ok = ok && writeAll(storage.data(), qnameLen);
      ok = ok && writeAll(&value.qtype, sizeof(value.qtype));
      ok = ok && writeAll(&value.qclass, sizeof(value.qclass));
      ok = ok && writeAll(&value.queryFlags, sizeof(value.queryFlags));
      uint8_t rudp = value.receivedOverUDP ? 1 : 0;
      uint8_t dok  = value.dnssecOK ? 1 : 0;
      uint8_t hasSub = value.subnet.has_value() ? 1 : 0;
      ok = ok && writeAll(&rudp, 1);
      ok = ok && writeAll(&dok, 1);
      ok = ok && writeAll(&hasSub, 1);
      if (hasSub) {
        std::string subStr = value.subnet->toString();
        uint16_t subLen = static_cast<uint16_t>(subStr.size());
        ok = ok && writeAll(&subLen, sizeof(subLen));
        ok = ok && writeAll(subStr.data(), subLen);
      }
      ok = ok && writeAll(&value.added, sizeof(value.added));
      ok = ok && writeAll(&value.validity, sizeof(value.validity));
      uint32_t valLen = static_cast<uint32_t>(value.value.size());
      ok = ok && writeAll(&valLen, sizeof(valLen));
      ok = ok && writeAll(value.value.data(), valLen);

      if (!ok) break;
      ++writtenCount;
    }
  }

  lseek(fd, countOffset, SEEK_SET);
  writeAll(&writtenCount, sizeof(writtenCount));
  close(fd);

  if (rename(tmpPath.c_str(), path.c_str()) != 0) {
    unlink(tmpPath.c_str());
    return false;
  }

  d_dirty.store(false);
  return true;
}

bool DNSDistPacketCache::load(const std::string& path)
{
  int fd = open(path.c_str(), O_RDONLY);
  if (fd < 0) {
    return false;
  }

  auto readAll = [fd](void* buf, size_t len) -> bool {
    char* p = static_cast<char*>(buf);
    size_t remaining = len;
    while (remaining > 0) {
      ssize_t n = read(fd, p, remaining);
      if (n <= 0) return false;
      p += n;
      remaining -= static_cast<size_t>(n);
    }
    return true;
  };

  char magic[4];
  uint32_t version = 0;
  if (!readAll(magic, 4) || memcmp(magic, s_persistentCacheMagic, 4) != 0 ||
      !readAll(&version, sizeof(version)) || version != s_persistentCacheVersion) {
    close(fd);
    return false;
  }

  uint32_t entryCount = 0;
  if (!readAll(&entryCount, sizeof(entryCount))) {
    close(fd);
    return false;
  }

  time_t now = time(nullptr);
  uint32_t loadedCount = 0;

  for (uint32_t i = 0; i < entryCount; ++i) {
    uint32_t key = 0;
    if (!readAll(&key, sizeof(key))) break;

    uint16_t qnameLen = 0;
    if (!readAll(&qnameLen, sizeof(qnameLen)) || qnameLen > 255) break;
    char qnameBuf[256];
    if (!readAll(qnameBuf, qnameLen)) break;

    DNSName qname;
    try {
      qname = DNSName(qnameBuf, qnameLen, 0, true);
    }
    catch (...) {
      break;
    }

    uint16_t qtype = 0, qclass = 0, queryFlags = 0;
    if (!readAll(&qtype, sizeof(qtype))) break;
    if (!readAll(&qclass, sizeof(qclass))) break;
    if (!readAll(&queryFlags, sizeof(queryFlags))) break;

    uint8_t rudp = 0, dok = 0, hasSub = 0;
    if (!readAll(&rudp, 1)) break;
    if (!readAll(&dok, 1)) break;
    if (!readAll(&hasSub, 1)) break;

    std::optional<Netmask> subnet;
    if (hasSub) {
      uint16_t subLen = 0;
      if (!readAll(&subLen, sizeof(subLen)) || subLen > 64) break;
      char subBuf[65];
      if (!readAll(subBuf, subLen)) break;
      try {
        subnet = Netmask(std::string(subBuf, subLen));
      }
      catch (...) {
      }
    }

    time_t added = 0, validity = 0;
    if (!readAll(&added, sizeof(added))) break;
    if (!readAll(&validity, sizeof(validity))) break;

    uint32_t valLen = 0;
    if (!readAll(&valLen, sizeof(valLen)) || valLen > 65535) break;
    std::string value(valLen, '\0');
    if (!readAll(value.data(), valLen)) break;

    if (validity <= now) {
      continue;
    }

    time_t remainingTTL = validity - now;

    CacheValue newValue;
    newValue.qname = std::move(qname);
    newValue.qtype = qtype;
    newValue.qclass = qclass;
    newValue.queryFlags = queryFlags;
    newValue.receivedOverUDP = (rudp != 0);
    newValue.dnssecOK = (dok != 0);
    newValue.subnet = subnet;
    newValue.added = now;
    newValue.validity = now + remainingTTL;
    newValue.len = static_cast<uint16_t>(valLen);
    newValue.value = std::move(value);

    uint32_t shardIndex = getShardIndex(key);
    auto& shard = d_shards.at(shardIndex);
    auto lock = shard.d_map.write_lock();
    if (insertLocked(*lock, key, newValue)) {
      ++shard.d_entriesCount;
      ++loadedCount;
    }
  }

  close(fd);
  return loadedCount > 0;
}
