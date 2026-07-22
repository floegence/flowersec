declare module "tr46" {
  type Options = Readonly<{
    checkHyphens?: boolean;
    checkBidi?: boolean;
    checkJoiners?: boolean;
    useSTD3ASCIIRules?: boolean;
    verifyDNSLength?: boolean;
    transitionalProcessing?: boolean;
    ignoreInvalidPunycode?: boolean;
  }>;

  const tr46: Readonly<{
    toASCII(domainName: string, options?: Options): string | null;
  }>;

  export default tr46;
}
