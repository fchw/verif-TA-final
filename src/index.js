import forge from "node-forge";
import crypto from "crypto";
import fs from "fs";
import pkg from '@ninja-labs/verify-pdf';  // ES6 

export class VerifyPdf {
  getSignature(pdf) {
    let byteRangePos = pdf.lastIndexOf("/ByteRange[");
    if (byteRangePos === -1) byteRangePos = pdf.lastIndexOf("/ByteRange [");

    const byteRangeEnd = pdf.indexOf("]", byteRangePos);
    const byteRange = pdf.slice(byteRangePos, byteRangeEnd + 1).toString();
    const byteRangeNumbers = /(\d+) +(\d+) +(\d+) +(\d+)/.exec(byteRange);
    // const byt/eRangeArr = null;
    try{
      const  byteRangeArr = byteRangeNumbers[0].split(" ");
    } catch(err) {
      const redText = "\x1b[31m%s\x1b[0m";
      console.log(redText, "Signature not found or document has been tempered");
      return {status : false, msg : "Signature not found or document has been tempered"};
    }
    const byteRangeArr = byteRangeNumbers[0].split(" ");

    const signedData = Buffer.concat([
      pdf.slice(parseInt(byteRangeArr[0]), parseInt(byteRangeArr[1])),
      pdf.slice(
        parseInt(byteRangeArr[2]),
        parseInt(byteRangeArr[2]) + parseInt(byteRangeArr[3])
      ),
    ]);
    let signatureHex = pdf
      .slice(
        parseInt(byteRangeArr[0]) + (parseInt(byteRangeArr[1]) + 1),
        parseInt(byteRangeArr[2]) - 1
      )
      .toString("binary");
    signatureHex = signatureHex.replace(/(?:00)*$/, "");
    const signature = Buffer.from(signatureHex, "hex").toString("binary");
    return { status:true, signature, signedData };
  }

  verify(pdf) {
    // Extracting the message from the signature
    const extractedData = this.getSignature(pdf);
    if(!extractedData.status) return extractedData
    // console.log("masuk",extractedData)
    const p7Asn1 = forge.asn1.fromDer(extractedData.signature);
    const message = forge.pkcs7.messageFromAsn1(p7Asn1);
    const {
      signature: sig,
      digestAlgorithm,
      authenticatedAttributes: attrs, // get list of list of auth attrs
    } = message.rawCapture;
    const set = forge.asn1.create(
      forge.asn1.Class.UNIVERSAL,
      forge.asn1.Type.SET,
      true,
      attrs
    );

    // Find hash algo
    const hashAlgorithmOid = forge.asn1.derToOid(digestAlgorithm);
    const hashAlgorithm = forge.pki.oids[hashAlgorithmOid].toUpperCase();

    // Create verifier
    const buf = Buffer.from(forge.asn1.toDer(set).data, "binary");
    const verifier = crypto.createVerify(`RSA-${hashAlgorithm}`);
    verifier.update(buf);

    // Verify stuff
    const cert = forge.pki.certificateToPem(message.certificates[0]);

    const validAuthenticatedAttributes = verifier.verify(cert, sig, "binary");
    if (!validAuthenticatedAttributes){
      // throw new Error("Wrong authenticated attributes");
      return {status : false, msg : "Wrong authenticated attributes"}
    }
      

    // Hash of non signature part of PDF
    const pdfHash = crypto.createHash(hashAlgorithm);
    const data = extractedData.signedData;
    pdfHash.update(data);

    // Extracting the message digest
    const oids = forge.pki.oids;
    const fullAttrDigest = attrs.find(
      (attr) => forge.asn1.derToOid(attr.value[0].value) === oids.messageDigest
    );
    const attrDigest = fullAttrDigest.value[1].value[0].value;

    // Compare to message digest to our PDF pdfHash
    const dataDigest = pdfHash.digest();
    const validContentDigest = dataDigest.toString("binary") === attrDigest;
    if (validContentDigest) {
      const greenText = "\x1b[32m%s\x1b[0m";
      console.log(greenText, "Digital Signature is valid and the PDF Content is not Tampered!!!");
      return {status : true, msg : "Digital Signature is valid and the PDF Content is not Tampered!!!"}
    } else {
      // throw new Error("Wrong content digest");
      return {status : false, msg : "Wrong content digest"}
    }
  }

  reason(pdf) {
    let reasonPos = pdf.lastIndexOf("/Reason (");
    if (reasonPos === -1) reasonPos = pdf.lastIndexOf("/Reason(");

    const reasonEnd = pdf.indexOf(")", reasonPos);
    const reason = pdf.slice(reasonPos + 9, reasonEnd).toString();
    // console.log()
    return "Alasan tanda tangan: ", reason
  }

  date(pdf) {
    let datePos = pdf.lastIndexOf("/M (D:");
    if (datePos === -1) datePos = pdf.lastIndexOf("/M(D:");

    const dateEnd = pdf.indexOf(")", datePos);
    const year = pdf.slice(datePos + 6, datePos+10).toString();
    const month = pdf.slice(datePos + 10, datePos+12).toString();
    const day = pdf.slice(datePos + 12, datePos+14).toString();
    const hour = pdf.slice(datePos + 14, datePos+16).toString();
    const minute = pdf.slice(datePos + 16, datePos+18).toString();
    const second = pdf.slice(datePos + 18, datePos+20).toString();
    // console.log()
    return "Timestamp: "+ day+"-"+ month+"-"+ year+" pukul "+ hour+":"+minute+":"+second +" GMT"
  }
}

function main() {
  const sign = new VerifyPdf();
  const signedPdfBuffer = fs.readFileSync("./ta2.pdf");
  console.log(signedPdfBuffer)
  sign.verify(signedPdfBuffer);
  sign.reason(signedPdfBuffer);
  sign.date(signedPdfBuffer)
  const { getCertificatesInfoFromPDF } = pkg;
  const certs = getCertificatesInfoFromPDF(signedPdfBuffer);
}
main();
