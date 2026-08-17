"use strict";

const MAX_IMAGE_BYTES = 32 * 1024 * 1024;
const MAX_DIMENSION = 100_000;

function asBytes(input) {
  const bytes = input instanceof ArrayBuffer
    ? new Uint8Array(input)
    : ArrayBuffer.isView(input)
      ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
      : null;
  if (!bytes || bytes.length === 0 || bytes.length > MAX_IMAGE_BYTES) throw new TypeError("Image metadata input is empty or exceeds 32 MiB");
  return bytes;
}
function ascii(bytes, start, end) { return String.fromCharCode(...bytes.subarray(start, end)); }
function uint16BE(bytes, offset) { if (offset + 2 > bytes.length) throw new TypeError("Truncated image metadata"); return (bytes[offset] << 8) | bytes[offset + 1]; }
function uint16LE(bytes, offset) { if (offset + 2 > bytes.length) throw new TypeError("Truncated image metadata"); return bytes[offset] | (bytes[offset + 1] << 8); }
function uint24LE(bytes, offset) { if (offset + 3 > bytes.length) throw new TypeError("Truncated image metadata"); return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16); }
function uint32BE(bytes, offset) { if (offset + 4 > bytes.length) throw new TypeError("Truncated image metadata"); return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(0, false); }
function dimensions(width, height, type) { if (!Number.isInteger(width) || !Number.isInteger(height) || width < 1 || height < 1 || width > MAX_DIMENSION || height > MAX_DIMENSION) throw new TypeError("Image dimensions are invalid or exceed 100,000 pixels"); return { width, height, type }; }
function png(bytes) { const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]; if (bytes.length < 24 || !signature.every((value, index) => bytes[index] === value)) return null; if (uint32BE(bytes, 8) !== 13 || ascii(bytes, 12, 16) !== "IHDR") throw new TypeError("Invalid PNG metadata header"); return dimensions(uint32BE(bytes, 16), uint32BE(bytes, 20), "png"); }
function gif(bytes) { if (bytes.length < 10 || !["GIF87a", "GIF89a"].includes(ascii(bytes, 0, 6))) return null; return dimensions(uint16LE(bytes, 6), uint16LE(bytes, 8), "gif"); }
const JPEG_START_OF_FRAME = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
function jpeg(bytes) { if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null; let offset = 2; while (offset < bytes.length) { while (offset < bytes.length && bytes[offset] === 0xff) offset += 1; if (offset >= bytes.length) break; const marker = bytes[offset]; offset += 1; if (marker === 0xd9 || marker === 0xda) break; if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue; const segmentLength = uint16BE(bytes, offset); if (segmentLength < 2 || offset + segmentLength > bytes.length) throw new TypeError("Invalid JPEG segment length"); if (JPEG_START_OF_FRAME.has(marker)) { if (segmentLength < 7) throw new TypeError("Invalid JPEG frame header"); return dimensions(uint16BE(bytes, offset + 3), uint16BE(bytes, offset + 5), "jpg"); } offset += segmentLength; } throw new TypeError("Invalid JPEG metadata header"); }
function webp(bytes) { if (bytes.length < 30 || ascii(bytes, 0, 4) !== "RIFF" || ascii(bytes, 8, 12) !== "WEBP") return null; const kind = ascii(bytes, 12, 16); if (kind === "VP8X") return dimensions(1 + uint24LE(bytes, 24), 1 + uint24LE(bytes, 27), "webp"); if (kind === "VP8L" && bytes[20] === 0x2f) { const width = 1 + (((bytes[22] & 0x3f) << 8) | bytes[21]); const height = 1 + (((bytes[24] & 0x0f) << 10) | (bytes[23] << 2) | ((bytes[22] & 0xc0) >> 6)); return dimensions(width, height, "webp"); } if (kind === "VP8 " && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) return dimensions(uint16LE(bytes, 26) & 0x3fff, uint16LE(bytes, 28) & 0x3fff, "webp"); throw new TypeError("Invalid WebP metadata header"); }
function svg(bytes) { const prefix = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, Math.min(bytes.length, 64 * 1024))); const root = prefix.match(/<svg\b[^>]*>/i)?.[0]; if (!root) return null; const parseLength = (name) => { const raw = root.match(new RegExp(`\\s${name}=["']([0-9]+(?:\\.[0-9]+)?)(?:px)?["']`, "i"))?.[1]; return raw ? Math.round(Number(raw)) : undefined; }; let width = parseLength("width"); let height = parseLength("height"); if (!width || !height) { const viewBox = root.match(/\sviewBox=["']\s*[-+]?\d+(?:\.\d+)?[ ,]+[-+]?\d+(?:\.\d+)?[ ,]+(\d+(?:\.\d+)?)[ ,]+(\d+(?:\.\d+)?)\s*["']/i); if (viewBox) { width ??= Math.round(Number(viewBox[1])); height ??= Math.round(Number(viewBox[2])); } } return dimensions(width, height, "svg"); }
function imageSize(input) { const bytes = asBytes(input); for (const parser of [png, gif, jpeg, webp, svg]) { const result = parser(bytes); if (result) return result; } throw new TypeError("Unsupported or unsafe image metadata format"); }
module.exports = imageSize;
module.exports.default = imageSize;
module.exports.imageSize = imageSize;
