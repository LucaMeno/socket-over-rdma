#pragma once
#include <cstdint>
#include <functional>  // std::hash
#include <arpa/inet.h> // ntohl
#include <common.h>    // sock_id_t

// Equality operator per sock_id_t
inline bool operator==(const sock_id_t &a, const sock_id_t &b) noexcept
{
    return a.sip == b.sip &&
           a.dip == b.dip &&
           a.sport == b.sport &&
           a.dport == b.dport;
}

namespace std
{
    template <>
    struct hash<sock_id_t>
    {
        std::size_t operator()(const sock_id_t &k) const noexcept
        {
            // Convert ip in host byte order
            uint32_t sip = ntohl(k.sip);
            uint32_t dip = ntohl(k.dip);
            uint16_t sport = k.sport;
            uint16_t dport = k.dport;

            std::size_t h1 = std::hash<uint32_t>{}(sip);
            std::size_t h2 = std::hash<uint32_t>{}(dip);
            std::size_t h3 = std::hash<uint16_t>{}(sport);
            std::size_t h4 = std::hash<uint16_t>{}(dport);

            std::size_t result = h1;
            result ^= h2 + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= h3 + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= h4 + 0x9e3779b9 + (result << 6) + (result >> 2);
            return result;
        }
    };
}
