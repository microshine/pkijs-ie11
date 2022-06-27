import * as pkijs from "https://unpkg.com/pkijs?module";
import * as utils from "https://unpkg.com/pvtsutils?module";
import { PemConverter } from "./pem.js";

function rawToArrayBuffer(raw: string | BufferSource): ArrayBuffer {
  if (utils.Convert.isHex(raw)) {
    return utils.Convert.FromHex(raw);
  } else if (utils.Convert.isBase64(raw)) {
    return utils.Convert.FromBase64(raw);
  } else if (utils.Convert.isBase64Url(raw)) {
    return utils.Convert.FromBase64Url(raw);
  } else if (PemConverter.isPem(raw)) {
    return PemConverter.decode(raw);
  } else if (utils.BufferSourceConverter.isBufferSource(raw)) {
    return utils.BufferSourceConverter.toArrayBuffer(raw);
  }

  throw new Error("Cannot convert raw data into ArrayBuffer. Unknown format.")
}

export interface ExtensionJson {
  type: string;
  critical: boolean;
  value: ArrayBuffer;
}

export type ExtensionMixed = ExtensionJson

export interface CertificateJson {
  version: number;
  notBefore: Date;
  notAfter: Date;
  issuer: Record<string, string>;
  subject: Record<string, string>;
  extensions: ExtensionMixed[]
}

export function certParse(raw: string | BufferSource): CertificateJson {
  const rawData = rawToArrayBuffer(raw);

  const cert = pkijs.Certificate.fromBER(rawData);

  const certJson: CertificateJson = {
    version: cert.version,
    notBefore: cert.notBefore.value,
    notAfter: cert.notAfter.value,
    issuer: {},
    subject: {},
    extensions: [],
  };

  for (const item of cert.issuer.typesAndValues) {
    certJson.issuer[item.type] = item.value.valueBlock.value;
  }
  for (const item of cert.subject.typesAndValues) {
    certJson.subject[item.type] = item.value.valueBlock.value;
  }
  if (cert.extensions) {
    for (const item of cert.extensions) {
      const extension: ExtensionJson = {
        type: item.extnID,
        critical: item.critical,
        value: item.extnValue.valueBlock.valueHexView,
      };

      certJson.extensions.push(extension);
    }
  }

  return certJson;
}