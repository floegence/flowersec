import tr46 from "tr46";

export type TR46Options = Readonly<{
  checkHyphens?: boolean;
  checkBidi?: boolean;
  checkJoiners?: boolean;
  useSTD3ASCIIRules?: boolean;
  verifyDNSLength?: boolean;
  transitionalProcessing?: boolean;
  ignoreInvalidPunycode?: boolean;
}>;

export function toASCII(domainName: string, options?: TR46Options): string | null {
  return tr46.toASCII(domainName, options);
}
