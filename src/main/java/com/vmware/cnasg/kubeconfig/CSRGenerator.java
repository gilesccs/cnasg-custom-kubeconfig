package com.vmware.cnasg.kubeconfig;

import io.fabric8.kubernetes.api.model.*;
import io.fabric8.kubernetes.client.internal.KubeConfigUtils;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class CSRGenerator {

        public static void main(String[] args) throws Exception
        {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            String commonName = "tuckkin@gmail.com";

            // 创建 CSR 对象
//            X500Principal subject = new X500Principal("C=CName, ST=STName, L=LName, O=OName, OU=OUName, CN=CNName, EMAILADDRESS=Name@gmail.com");
            X500Principal subject = new X500Principal("CN=" + commonName);
            ContentSigner signGen = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
            // 添加 SAN 扩展
//            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
//            GeneralNames generalNames = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.rfc822Name, "ip=6.6.6.6"), new GeneralName(GeneralName.rfc822Name, "email=666@gmail.com")});
//            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, generalNames);
//            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
            // build csr
            PKCS10CertificationRequest csr = builder.build(signGen);
            // 输出 PEM 格式的 CSR
//            OutputStreamWriter output = new OutputStreamWriter(System.out);
            StringWriter output = new StringWriter();
            JcaPEMWriter pem = new JcaPEMWriter(output);
            pem.writeObject(csr);
            pem.close();
            output.close();
            System.out.println(output);
            System.out.println(Base64.getEncoder().encodeToString(output.toString().getBytes()));

            Cluster cluster = new ClusterBuilder()
                    .withServer("https://tp-apiserver-523837663.us-east-1.elb.amazonaws.com:6443")
                    .withCertificateAuthorityData("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1lUQ0NBVWtDQVFBd0hERWFNQmdHQTFVRUF3d1JkSFZqYTJ0cGJrQm5iV0ZwYkM1amIyMHdnZ0VpTUEwRwpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ0FjRVRmSjlacGxiRnR3Wmc2Y1l3VUZsOEk1NTNzCkZCVVFGQ2RIQkVZVmZaWnVPL3FTbEUvcHM3R1dpVG1DYUgrbXNlMUd6SXZYZEliVGRNQmxPL2NzQm5nT3lDS3cKRXMwbkZCYVZnRDJnZWluWnFWcUtXanVyVVZ4SlhJc0g0dnlJNnc2ODBuQTFMRE5TZDQ4Vkg3Q0FkM0JrWUVPTgpCeW9Mb0hkRkdzczcvbHVDMStTS2oyb0xpdnlUN3kvRDJwZUQzY0ZVY1FXSDdjSitmZTJIR2FvY1BSWjdUZ0pSCm5IQklwUTRkS0ZPNmszMUZIVkRNVXJ3VzNpWjBGbzJhcEo1b0I5R3hCZ0lBVnVmMzlGRk9JenozREh0K08yQTkKa05FWDJRMzREcHJPOXhYVUQza2lJTzNOYWw3Y3ZiMWF6MHdHZDFXblc4Z2c5b0Rnek9JemdOZVBBZ01CQUFHZwpBREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBVVNPTGNrTjNxZVo5TStZWVJQTm9GNWZLM1cza3E0TjhNSHA1CjVGc1o0VklJd0F0YzVZUVFqb3A2N3hzRDZobnFRcHVxV3BPNVAvRGxIVnhOSjhVZEFNL0lzYkVDc1AzZjZCR3IKbUJEV1FxUCtub0MrWXVhNnV3SlYxbm1oQktRT3kzaUJCQWM5ZTBpWTBIVGRvWHo0bW5qN1U0RVNHb2JmQ3JGVgpsU096N3U4L0hqSFVyYzZNek5YaHdUdTlURHlZcGNuQ2xaenIxeDM3NDJ2Y2RYbk9nQkY4dHFpUnA5R2VuaXd3CkNEeWZob3Q1MHJ3eGxnMVl2bUlyNWtjT3VyNmFSUWxzWUdFcHUza1hBU01iZW9Ybld2WXlDdXFXbDQ4aFNUR00KM0lwMnpjVTM3UndSMlFlZzJZV1Q1UHVsT3d6aXJmbDJhd2p6QUdudUlRQjJRT0EzNFE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K")
                    .build();
            NamedCluster namedCluster = new NamedClusterBuilder()
                    .withCluster(cluster)
                    .withName("smu")
                    .build();
            List<NamedCluster> namedClusters = new ArrayList<>();
            namedClusters.add(namedCluster);

            AuthInfo authInfo = new AuthInfoBuilder()
                    .withClientCertificateData("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1lUQ0NBVWtDQVFBd0hERWFNQmdHQTFVRUF3d1JkSFZqYTJ0cGJrQm5iV0ZwYkM1amIyMHdnZ0VpTUEwRwpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ1IyVFJBTnBQVFlRNjRsM01POHMrZGxBTXV4K3pQClVJck53RGowNy9DOE1qb3g4S3BIVmtXOVRGTEFYQmQ0eGhjWkRmUzEzaEhSVUhHRTNXaFFsT1RQSkU2Yjl2dnMKWWNJcVphTmFrZktHbXh4cGI3ZW5mR1kyUzVyc1JMVEJJTlhkYTBwcTlyVzF2NEZzY2wxTXVDb2pjN1VkOTdsegpkYjBTeDJYaEJXVE9uSzF6NkF2ZGE4VGtJcXphZTFtWE9HdUsvUCtleFhYbFBlZ3BYRlJjUzRMczExTnRjU29mCklRRVc0ZmtBOExCa2FGNFNLVWlySE4vQ1FZL1VkSExZZ2JERFBVREdDa3ZEUms0dHdsektmaGxYWlZuSG9XMXEKY1B0WlFxeWhqcHkwL3VjdEJuQVBjbmUreWQ5SVJiL2cyR1IvR1E3VlVMa1JzSHI4dVhlcVJVdmhBZ01CQUFHZwpBREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBSlc3MUZONFRVYjc1MHNzYUxFMGNGL1htdGFWelp0U0dIOEU2CnMzd1crTDhxZklzcnlxRXVybGxpS3RLbUNzVmd4SmR6M243R0x4Ym01K0ZJSkI5bVdpK3R5R285L2haWXR2N3MKOTVCejNIaFVQS2dVNFBhQWE0T2FkVDNUZzhNQjN0M2RRUGNJYzR1MVFyaG4yMGtJa2phUzhRODBTZDZhMGozRApuVGJ5bVNRVG5keUVSUGlTUFF3TDZTYVh1N3VHUDB4cVVvQUNOSWtJK1pmNnMwbGJxRkRzcndNSHhoaHJJSlhnCmdCaVZGYzlqdnozVndESmw3ZXIzRXhWc0tiWXJyNkF4TDI0b3lGSjlma3RYUkE1b3BkcWM1YkY0bWdYbGFQd1IKQWwvcElxZCtSSUxCV3BGR001M2VYVkhhZTFPQ1UxVVlCUS9zbTF1Z0dpN0haUjNuMVE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K")
                    .withClientKeyData("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ1lUQ0NBVWtDQVFBd0hERWFNQmdHQTFVRUF3d1JkSFZqYTJ0cGJrQm5iV0ZwYkM1amIyMHdnZ0VpTUEwRwpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQ1IyVFJBTnBQVFlRNjRsM01POHMrZGxBTXV4K3pQClVJck53RGowNy9DOE1qb3g4S3BIVmtXOVRGTEFYQmQ0eGhjWkRmUzEzaEhSVUhHRTNXaFFsT1RQSkU2Yjl2dnMKWWNJcVphTmFrZktHbXh4cGI3ZW5mR1kyUzVyc1JMVEJJTlhkYTBwcTlyVzF2NEZzY2wxTXVDb2pjN1VkOTdsegpkYjBTeDJYaEJXVE9uSzF6NkF2ZGE4VGtJcXphZTFtWE9HdUsvUCtleFhYbFBlZ3BYRlJjUzRMczExTnRjU29mCklRRVc0ZmtBOExCa2FGNFNLVWlySE4vQ1FZL1VkSExZZ2JERFBVREdDa3ZEUms0dHdsektmaGxYWlZuSG9XMXEKY1B0WlFxeWhqcHkwL3VjdEJuQVBjbmUreWQ5SVJiL2cyR1IvR1E3VlVMa1JzSHI4dVhlcVJVdmhBZ01CQUFHZwpBREFOQmdrcWhraUc5dzBCQVFzRkFBT0NBUUVBSlc3MUZONFRVYjc1MHNzYUxFMGNGL1htdGFWelp0U0dIOEU2CnMzd1crTDhxZklzcnlxRXVybGxpS3RLbUNzVmd4SmR6M243R0x4Ym01K0ZJSkI5bVdpK3R5R285L2haWXR2N3MKOTVCejNIaFVQS2dVNFBhQWE0T2FkVDNUZzhNQjN0M2RRUGNJYzR1MVFyaG4yMGtJa2phUzhRODBTZDZhMGozRApuVGJ5bVNRVG5keUVSUGlTUFF3TDZTYVh1N3VHUDB4cVVvQUNOSWtJK1pmNnMwbGJxRkRzcndNSHhoaHJJSlhnCmdCaVZGYzlqdnozVndESmw3ZXIzRXhWc0tiWXJyNkF4TDI0b3lGSjlma3RYUkE1b3BkcWM1YkY0bWdYbGFQd1IKQWwvcElxZCtSSUxCV3BGR001M2VYVkhhZTFPQ1UxVVlCUS9zbTF1Z0dpN0haUjNuMVE9PQotLS0tLUVORCBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0K")
                    .build();
            NamedAuthInfo namedAuthInfo = new NamedAuthInfoBuilder()
                    .withName("tuckkin")
                    .withUser(authInfo)
                    .build();
            List<NamedAuthInfo> namedAuthInfos = new ArrayList<>();
            namedAuthInfos.add(namedAuthInfo);

            Context context = new ContextBuilder()
                    .withCluster(namedCluster.getName())
                    .withUser(namedAuthInfo.getName())
                    .build();
            NamedContext namedContext = new NamedContextBuilder()
                    .withContext(context)
                    .withName(namedAuthInfo.getName() + "@" + namedCluster.getName())
                    .build();
            List<NamedContext> namedContexts = new ArrayList<>();
            namedContexts.add(namedContext);

            Config config = new ConfigBuilder()
                    .withApiVersion("v1")
                    .withKind("Config")
                    .withClusters(namedClusters)
                    .withContexts(namedContexts)
                    .withUsers(namedAuthInfos)
                    .withCurrentContext(namedContext.getName())
                    .build();

//            String configStr = SerializationUtils.dumpAsYaml(new CertificateSigningRequestBuilder().build());
            KubeConfigUtils.persistKubeConfigIntoFile(config,"/tmp/" + namedContext.getName());
            String content = Files.readString(Paths.get("/tmp/" + namedContext.getName()));
            System.out.println(content);
        }
}
