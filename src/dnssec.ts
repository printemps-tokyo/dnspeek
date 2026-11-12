/**
 * DNSSEC status from the resolver's point of view. node:dns cannot ask for
 * DNSSEC or show the AD (authenticated data) bit, so this sends its own DNS
 * query over UDP (RFC 1035 wire format) with an EDNS0 OPT record whose DO
 * bit asks for DNSSEC (RFC 3225) and the AD bit set (RFC 6840 5.7), and reads
 * the answer's header: AD means the resolver validated it. A DS record at the
 * parent means the zone is signed.
 */
import { createSocket } from "node:dgram";
import { randomInt } from "node:crypto";
import { isIP } from "node:net";

export const TYPE = { A: 1, NS: 2, SOA: 6, MX: 15, DS: 43, DNSKEY: 48 } as const;

/** A DNS query for `name`/`qtype` with RD, AD and EDNS0 DO set. */
export function buildQuery(id: number, name: string, qtype: number): Buffer {
  const labels = name.replace(/\.$/, "").split(".").filter((l) => l !== "");
  const qname = Buffer.concat([
    ...labels.map((l) => {
      const b = Buffer.from(l, "ascii");
      if (b.length > 63) throw new Error(`label "${l}" is longer than 63 bytes`);
      return Buffer.concat([Buffer.from([b.length]), b]);
    }),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0120, 2); // RD (recursion desired) + AD
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(1, 10); // ARCOUNT: the OPT record
  const question = Buffer.alloc(4);
  question.writeUInt16BE(qtype, 0);
  question.writeUInt16BE(1, 2); // IN
  // OPT: root name, type 41, class = UDP payload size, TTL = ext-rcode,
  // version, flags (DO = 0x8000), empty RDATA.
  const opt = Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
  return Buffer.concat([header, qname, question, opt]);
}

export interface DnsAnswer {
  id: number;
  rcode: number;
  /** The AD (authenticated data) bit. */
  ad: boolean;
  truncated: boolean;
  /** Answer-section record types, in order. */
  answerTypes: number[];
}

/** Skip a (possibly compressed) domain name; returns the offset after it. */
function skipName(buf: Buffer, at: number): number {
  for (;;) {
    if (at >= buf.length) throw new Error("truncated name");
    const len = buf[at]!;
    if (len === 0) return at + 1;
    if ((len & 0xc0) === 0xc0) return at + 2;
    at += 1 + len;
  }
}

/** Parse the header and answer types of a DNS response. */
export function parseAnswer(buf: Buffer): DnsAnswer {
  if (buf.length < 12) throw new Error("DNS response shorter than a header");
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  let at = 12;
  for (let i = 0; i < qd; i++) at = skipName(buf, at) + 4;
  const answerTypes: number[] = [];
  for (let i = 0; i < an; i++) {
    at = skipName(buf, at);
    if (at + 10 > buf.length) throw new Error("truncated answer");
    answerTypes.push(buf.readUInt16BE(at));
    at += 10 + buf.readUInt16BE(at + 8);
  }
  return { id: buf.readUInt16BE(0), rcode: flags & 0x0f, ad: (flags & 0x0020) !== 0, truncated: (flags & 0x0200) !== 0, answerTypes };
}

/** Send one query over UDP and parse the matching answer. */
export function queryUdp(server: string, name: string, qtype: number, timeoutMs = 5000): Promise<DnsAnswer> {
  const host = server.replace(/^\[|\]$/g, "");
  const family = isIP(host) === 6 ? "udp6" : "udp4";
  const id = randomInt(0, 0x10000);
  const packet = buildQuery(id, name, qtype);
  return new Promise((resolve, reject) => {
    const socket = createSocket(family);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error(`no answer from ${server} within ${timeoutMs}ms`));
    }, timeoutMs);
    socket.on("message", (msg) => {
      try {
        const answer = parseAnswer(msg);
        if (answer.id !== id) return; // not ours
        clearTimeout(timer);
        socket.close();
        resolve(answer);
      } catch (err) {
        clearTimeout(timer);
        socket.close();
        reject(err as Error);
      }
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      socket.close();
      reject(err);
    });
    socket.send(packet, 53, host);
  });
}

export interface DnssecStatus {
  resolver: string;
  /** The parent publishes a DS record for the domain: the zone is signed. */
  signed: boolean;
  /** The resolver set AD on the DS answer and on the domain's own data. */
  validated: boolean;
  /** SERVFAIL from the resolver, which a validating resolver returns for bogus data. */
  servfail: boolean;
}

/** Ask `resolver` about the domain's DS record and its NS (or SOA) data. */
export async function dnssecStatus(
  domain: string,
  resolver: string,
  timeoutMs = 5000,
  query: typeof queryUdp = queryUdp,
): Promise<DnssecStatus> {
  const [ds, own] = await Promise.all([
    query(resolver, domain, TYPE.DS, timeoutMs),
    query(resolver, domain, TYPE.SOA, timeoutMs),
  ]);
  const servfail = ds.rcode === 2 || own.rcode === 2;
  const signed = ds.answerTypes.includes(TYPE.DS);
  return { resolver, signed, validated: signed && ds.ad && own.ad && !servfail, servfail };
}
