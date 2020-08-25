/* 
Copyright (c) 2010, NHIN Direct Project
All rights reserved.

Authors:
   Greg Meyer      gm2552@cerner.com
 
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
in the documentation and/or other materials provided with the distribution.  Neither the name of the The NHIN Direct Project (nhindirect.org). 
nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
THE POSSIBILITY OF SUCH DAMAGE.
*/

package org.directtruststandards.timplus.tools.certgen;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

/**
 * Engine for generating self signed certificates and leaf node certificates.
 * @author Greg Meyer
 *
 */
///CLOVER:OFF
public class CertGenerator 
{
	private static final String PBE_WITH_MD5_AND_DES_CBC_OID  = "1.2.840.113549.1.5.3";
	
	public static CertCreateFields createCertificate(CertCreateFields fields) throws Exception
	{
		// generate a key pair first using RSA and a key strength provided by the user
		KeyPairGenerator kpg = (KeyPairGenerator) KeyPairGenerator.getInstance("RSA", "BC");
		
		kpg.initialize(fields.getKeyStrength(), new SecureRandom());
		
		KeyPair keyPair = kpg.generateKeyPair();
		
		if (fields.getSignerCert() == null)
			// this is request for a new CA
			return createNewCA(fields, keyPair);
		else
			// new leaf certificate request
			return createLeafCertificate(fields, keyPair);		
	}	
	
	public static long generatePositiveRandom()
	{
		Random ranGen;
		long retVal = -1;
		byte[] seed = new byte[8];
		VMPCRandomGenerator seedGen = new VMPCRandomGenerator();
		seedGen.addSeedMaterial(new SecureRandom().nextLong());
		seedGen.nextBytes(seed);
		ranGen = new SecureRandom(seed);
		while (retVal < 1)
		{
			retVal = ranGen.nextLong(); 						
		}
		
		return retVal;
	}
	
	public static X509Certificate createCertFromCSR(PemObject certReq, CertCreateFields signerCert) throws Exception
	{
		/*
		certReq.verify();
		
		final CertificationRequestInfo reqInfo = certReq.getCertificationRequestInfo();

		final X509V3CertificateGenerator  v1CertGen = new X509V3CertificateGenerator();
		final Calendar start = Calendar.getInstance();
		final Calendar end = Calendar.getInstance();
		end.add(Calendar.YEAR, 3); 
		
        v1CertGen.setSerialNumber(BigInteger.valueOf(generatePositiveRandom()));
        v1CertGen.setIssuerDN(signerCert.getSignerCert().getSubjectX500Principal()); // issuer is the parent cert
        v1CertGen.setNotBefore(start.getTime());
        v1CertGen.setNotAfter(end.getTime());
        v1CertGen.setSubjectDN(new X509Principal(reqInfo.getSubject().toString()));
        v1CertGen.setPublicKey(certReq.getPublicKey());
        v1CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        
        final ASN1Set attributesAsn1Set = reqInfo.getAttributes();
        
        X509Extensions certificateRequestExtensions = null;
        for (int i = 0; i < attributesAsn1Set.size(); ++i)
        {
           // There should be only only one attribute in the set. (that is, only
           // the `Extension Request`, but loop through to find it properly)
           final DEREncodable derEncodable = attributesAsn1Set.getObjectAt( i );
           
           
           if (derEncodable instanceof DERSequence)
           {
              final Attribute attribute = new Attribute( (DERSequence) attributesAsn1Set
                    .getObjectAt( i ) );

              if (attribute.getAttrType().equals( PKCSObjectIdentifiers.pkcs_9_at_extensionRequest ))
              {
                 // The `Extension Request` attribute is present.
                 final ASN1Set attributeValues = attribute.getAttrValues();

                 // The X509Extensions are contained as a value of the ASN.1 Set.
                 // Assume that it is the first value of the set.
                 if (attributeValues.size() >= 1)
                 {
                    certificateRequestExtensions = new X509Extensions( (ASN1Sequence) attributeValues
                          .getObjectAt( 0 ) );

                    // No need to search any more.
                    //break;
                 }
              }
           }
        }

        @SuppressWarnings("unchecked")
		Enumeration<DERObjectIdentifier> oids = certificateRequestExtensions.oids();
        while (oids.hasMoreElements())
        {
        	DERObjectIdentifier oid = oids.nextElement();
        	X509Extension ex = certificateRequestExtensions.getExtension(oid);
        	
        	v1CertGen.addExtension(oid, ex.isCritical(), X509Extension.convertValueToObject(ex));
        }
        
        return v1CertGen.generate((PrivateKey)signerCert.getSignerKey(), CryptoExtensions.getJCEProviderName());
        */
		return null;
	}
	
	private static CertCreateFields createNewCA(CertCreateFields fields, KeyPair keyPair) throws Exception
	{
		StringBuilder dnBuilder = new StringBuilder();
		
		String altName = "";
		
		// create the DN
		if (fields.getAttributes().containsKey("EMAILADDRESS"))
		{
			dnBuilder.append("E=").append(fields.getAttributes().get("EMAILADDRESS")).append(", ");
			altName = fields.getAttributes().get("EMAILADDRESS").toString();
		}
		
		if (fields.getAttributes().containsKey("CN"))
			dnBuilder.append("CN=").append(fields.getAttributes().get("CN")).append(", ");
		
		if (fields.getAttributes().containsKey("C"))
			dnBuilder.append("C=").append(fields.getAttributes().get("C")).append(", ");
		
		if (fields.getAttributes().containsKey("ST"))
			dnBuilder.append("ST=").append(fields.getAttributes().get("ST")).append(", ");	
		
		if (fields.getAttributes().containsKey("L"))
			dnBuilder.append("L=").append(fields.getAttributes().get("L")).append(", ");	
		
		if (fields.getAttributes().containsKey("O"))
			dnBuilder.append("O=").append(fields.getAttributes().get("O")).append(", ");				
		
		String DN = dnBuilder.toString().trim();
		if (DN.endsWith(","))
			DN = DN.substring(0, DN.length() - 1);
		
		X509V3CertificateGenerator  v1CertGen = new X509V3CertificateGenerator();
		
		Calendar start = Calendar.getInstance();
		Calendar end = Calendar.getInstance();
		end.add(Calendar.DAY_OF_MONTH, fields.getExpDays()); 
		
        v1CertGen.setSerialNumber(BigInteger.valueOf(generatePositiveRandom()));
        v1CertGen.setIssuerDN(new X509Principal(DN));
        v1CertGen.setNotBefore(start.getTime());
        v1CertGen.setNotAfter(end.getTime());
        v1CertGen.setSubjectDN(new X509Principal(DN)); // issuer and subject are the same for a CA
        v1CertGen.setPublicKey(keyPair.getPublic());
        v1CertGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        v1CertGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        
        
        X509Certificate newCACert = v1CertGen.generate(keyPair.getPrivate(), "BC");
        
        // validate the certificate 
        newCACert.verify(keyPair.getPublic());
        
        // write the certificate the file system
        writeCertAndKey(newCACert, keyPair.getPrivate(), fields);
       
        return fields;
	}
	
	private static CertCreateFields createLeafCertificate(CertCreateFields fields, KeyPair keyPair) throws Exception
	{
		StringBuilder dnBuilder = new StringBuilder();
		

		/*
		 * Create the DN
		 */
		if (fields.getAttributes().containsKey("CN"))
			dnBuilder.append("CN=").append(fields.getAttributes().get("CN")).append(", ");
		
		if (fields.getAttributes().containsKey("C"))
			dnBuilder.append("C=").append(fields.getAttributes().get("C")).append(", ");
		
		if (fields.getAttributes().containsKey("ST"))
			dnBuilder.append("ST=").append(fields.getAttributes().get("ST")).append(", ");	
		
		if (fields.getAttributes().containsKey("L"))
			dnBuilder.append("L=").append(fields.getAttributes().get("L")).append(", ");	
		
		if (fields.getAttributes().containsKey("O"))
			dnBuilder.append("O=").append(fields.getAttributes().get("O")).append(", ");				
		
		String DN = dnBuilder.toString().trim();
		if (DN.endsWith(","))
			DN = DN.substring(0, DN.length() - 1);
		
		
		/*
		 * Create the valid dates
		 */
		Calendar start = Calendar.getInstance();
		Calendar end = Calendar.getInstance();
		end.add(Calendar.DAY_OF_MONTH, fields.getExpDays()); 
		
		/*
		 * General cert fields
		 */
		final X509v3CertificateBuilder  v1CertGen = new X509v3CertificateBuilder(new X500Name(fields.getSignerCert().getIssuerDN().toString()), 
				BigInteger.valueOf(generatePositiveRandom()), start.getTime(), end.getTime(), new X500Name(DN), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        
		/*
		 * Auth Key ID
		 */
        v1CertGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
        		new AuthorityKeyIdentifierStructure(fields.getSignerCert().getPublicKey()));


        /*
         * Extended Key Usage
         */
        final KeyPurposeId[] keyPurposes = {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth};
        v1CertGen.addExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(keyPurposes));
        
        
        /*
         * Basic Constraint (critial)
         */
        v1CertGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        
        
        /*
         * Key Usage (critial)
         */
        int keyUsage = KeyUsage.keyEncipherment | KeyUsage.digitalSignature;
        v1CertGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage));
        	
        	
        /*
         * Subject Alt Names
         */
        final String domain = (String)fields.getAttributes().get("DOMAIN");

        final GeneralName subjectAltName = new GeneralName(GeneralName.dNSName, domain);
        final GeneralName ftAltName = new GeneralName(GeneralName.dNSName, "ftproxystream." + domain);
        final GeneralName groupChatAltName = new GeneralName(GeneralName.dNSName, "groupchat." + domain);

        final GeneralName[] names = new GeneralName[] {subjectAltName, ftAltName, groupChatAltName};//, xmppServerAltName, xmppClientAltName};
        final DERSequence namesSeq = new DERSequence(names);
        
        v1CertGen.addExtension(X509Extensions.SubjectAlternativeName, false, namesSeq);
        
        /*
         * CRL Distribution Point
         */
        final String crlURL = (String)fields.getAttributes().get("CRL");
        
        final GeneralNames distPointGenNames = new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlURL));	
        final DistributionPointName distPointName = new DistributionPointName(distPointGenNames);
        final DistributionPoint point = new DistributionPoint(distPointName, null, null);
        final DistributionPoint[] points = new  DistributionPoint[] {point};
        final CRLDistPoint distPoint = new CRLDistPoint(points);
        v1CertGen.addExtension(X509Extensions.CRLDistributionPoints, false, distPoint);
        
        /*
         * Sign the certificate
         */
        ContentSigner signer = new JcaContentSignerBuilder( "SHA256WithRSAEncryption" ).build((PrivateKey)fields.getSignerKey());
        X509CertificateHolder certHolder = v1CertGen.build(signer);
        final X509Certificate newClientCert = new JcaX509CertificateConverter().getCertificate( certHolder );
        
        // validate the certificate 
        newClientCert.verify(fields.getSignerCert().getPublicKey());
        
        // write the certificate the file system
        writeCertAndKey(newClientCert, keyPair.getPrivate(), fields);
       
        return fields;
	}	
	
	private static void writeCertAndKey(X509Certificate cert, PrivateKey key, CertCreateFields fields) throws Exception
	{
		// write the cert
		FileUtils.writeByteArrayToFile(fields.getNewCertFile(), cert.getEncoded());		
		
		if (fields.getNewPassword() == null || fields.getNewPassword().length == 0)
		{
			// no password... just write the file 
			FileUtils.writeByteArrayToFile(fields.getNewKeyFile(), key.getEncoded());
		}
		else
		{
			// encypt it, then write it
			
			// prime the salts
			byte[] salt = new byte[8];
			VMPCRandomGenerator ranGen = new VMPCRandomGenerator();
			ranGen.addSeedMaterial(new SecureRandom().nextLong());
			ranGen.nextBytes(salt);

			// create PBE parameters from salt and iteration count
			PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, 20);
			   

			PBEKeySpec pbeKeySpec = new PBEKeySpec(fields.getNewPassword());
			SecretKey sKey = SecretKeyFactory.getInstance("PBEWithMD5AndDES", "BC").generateSecret(pbeKeySpec); 
			
			// encrypt
			Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES", "BC");
			cipher.init(Cipher.ENCRYPT_MODE, sKey, pbeSpec, null);
			byte[] plain = (byte[])key.getEncoded();
			byte[] encrKey = cipher.doFinal(plain, 0, plain.length);

			// set the algorithm parameters
			AlgorithmParameters pbeParams = AlgorithmParameters.getInstance(PBE_WITH_MD5_AND_DES_CBC_OID, Security.getProvider("SunJCE"));

			pbeParams.init(pbeSpec);

			// place in a EncryptedPrivateKeyInfo to encode to the proper file format
			EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(pbeParams,encrKey);
			
			// now write it to the file
			FileUtils.writeByteArrayToFile(fields.getNewKeyFile(), info.getEncoded());
		}
			
		if (fields.getSignerCert() == null)
			fields.setSignerCert(cert);
		
		if (fields.getSignerKey() == null)
			fields.setSignerKey(key);
	}
}
///CLOVER:ON