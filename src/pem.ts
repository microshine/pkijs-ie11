import * as utils from "https://unpkg.com/pvtsutils?module";

const PEM_PATTERN = /-{5}BEGIN [A-Z0-9 ]+-{5}([a-zA-Z0-9=+/\n\r]+)-{5}END [A-Z0-9 ]+-{5}/g;

export class PemConverter {
  public static isPem(data: unknown): data is string {
    return typeof data === "string"
      && new RegExp(PEM_PATTERN).test(data);
  }

  /**
   * Decodes a PEM string into a byte array
   * @param pem message in PEM format
   */
  public static decode(pem: string): ArrayBuffer {
    const pattern = new RegExp(PEM_PATTERN);

    const matches = pattern.exec(pem);
    if (matches) {
      const base64 = matches[1]
        .replace(/[\r\n]/g, "")

      return utils.Convert.FromBase64(base64);
    }

    throw new Error("Cannot convert the PEM string into ArrayBuffer. Incorrect string format.");
  }

}