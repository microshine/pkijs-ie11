import * as utils from "https://unpkg.com/pvtsutils?module";
import { certParse } from "./cert_parser.js";
import { getOidName } from "./oid.js";

const $certRaw = document.getElementById("cert-raw") as HTMLTextAreaElement;
const $certParse = document.getElementById("cert-parse") as HTMLButtonElement;
const $certLog = document.getElementById("cert-log") as HTMLElement;

$certParse.addEventListener("click", parse);
const SPACE_CHAR = " ";

function log(writer: string[], key: string, value: string[] | string | number | boolean | Date | null, padding = 0) {
  const leftPart = `${"".padStart(2 * padding, SPACE_CHAR)}${`${key}:`.padEnd(20, SPACE_CHAR)}`;
  if (Array.isArray(value)) {
    writer.push(`${leftPart}${value[0] ?? ""}`);
    for (let i = 1; i < value.length; i++) {
      const item = value[i];
      writer.push(`${"".padStart(leftPart.length, SPACE_CHAR)}${item}`);
    }
  } else {
    writer.push(`${leftPart}${value === null ? "" : value}`);
  }
}

function parse() {
  const certRaw = $certRaw.value;
  const certJson = certParse(certRaw);

  // clear log
  $certLog.innerText = "";

  const writer: string[] = [];
  log(writer, "Certificate", null);
  log(writer, "Version", certJson.version, 1);
  log(writer, "Not before", certJson.notBefore.toISOString(), 1);
  log(writer, "Not after", certJson.notAfter.toISOString(), 1);
  log(writer, "Issuer", null, 1);
  for (const key in certJson.issuer) {
    log(writer, getOidName(key), certJson.issuer[key], 2);
  }
  log(writer, "Subject", null, 1);
  for (const key in certJson.subject) {
    log(writer, getOidName(key), certJson.subject[key], 2);
  }
  log(writer, "Extensions", null, 1);
  for (let i = 0; i < certJson.extensions.length; i++) {
    const extension = certJson.extensions[i];

    log(writer, `Extension #${i + 1}`, null, 3);
    log(writer, "Type", `${getOidName(extension.type)} (${extension.type})`, 4);
    log(writer, "Critical", extension.critical, 4);
    log(writer, "Value", utils.Convert.ToHex(extension.value).replace(/(.{32})/g, "$1\n").split("\n"), 4);
  }

  $certLog.innerText = writer.join("\n");
}
