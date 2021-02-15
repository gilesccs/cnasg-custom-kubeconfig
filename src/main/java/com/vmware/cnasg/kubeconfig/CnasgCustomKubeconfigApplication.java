package com.vmware.cnasg.kubeconfig;

import com.vmware.cnasg.kubeconfig.watcher.CertificateSigningRequestWatcher;
import io.fabric8.kubernetes.api.model.Namespace;
import io.fabric8.kubernetes.api.model.ObjectMeta;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequest;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequestBuilder;
import io.fabric8.kubernetes.client.Config;
import io.fabric8.kubernetes.client.DefaultKubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.internal.SerializationUtils;
import io.fabric8.kubernetes.client.utils.HttpClientUtils;
import okhttp3.OkHttpClient;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import javax.annotation.PreDestroy;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

@SpringBootApplication
public class CnasgCustomKubeconfigApplication implements CommandLineRunner {

    public static final Logger logger =
            LoggerFactory.getLogger(CnasgCustomKubeconfigApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(CnasgCustomKubeconfigApplication.class, args);
    }

    @Override
    public void run(String... arg0) throws Exception {

        Resource resource = new ClassPathResource("kubeconfig");
        InputStream inputStream = resource.getInputStream();
        byte[] bdata = FileCopyUtils.copyToByteArray(inputStream);
        String kubeConfig = new String(bdata, StandardCharsets.UTF_8);

        KubernetesClient k8sClient = null;
        try {
            k8sClient = new DefaultKubernetesClient(Config.fromKubeconfig(kubeConfig));
            logger.info("Kubernetes Client created");
        } catch (IOException e) {
            logger.error("error",e);
        }

        String USERNAME = "tuckkin";
        KeyPair keyPair = generateRSAKeyPair();
        String encodedCSR = generateEncodedCSR(keyPair,USERNAME);
        String encodedPrivateKey = generateEncodedSecretKey(keyPair.getPrivate());
//        String encodedPublicKey = generateEncodedSecretKey(keyPair.getPublic());

        Map<String,String> annotations = new HashMap<>();
        annotations.put("self-service-csr-request","true");
        annotations.put("private-key",encodedPrivateKey);
//        annotations.put("public-key",encodedPublicKey);

        CertificateSigningRequest tmpCSR = k8sClient.certificateSigningRequests().withName(USERNAME).get();
        if (tmpCSR == null) {
            k8sClient.certificateSigningRequests().watch(new CertificateSigningRequestWatcher(k8sClient));
            CertificateSigningRequest csr = new CertificateSigningRequestBuilder()
                    .withNewMetadata()
                    .withName(USERNAME)
                    .withAnnotations(annotations)
                    .endMetadata()
                    .withNewSpec()
                    .addNewGroup("system:authenticated")
                    .withRequest(encodedCSR)
                    .withSignerName("kubernetes.io/kube-apiserver-client")
                    .addNewUsage("client auth")
                    .endSpec()
                    .build();
            k8sClient.certificateSigningRequests().create(csr);
            logger.info("CSR["+USERNAME+"] created");
        } else {
            logger.info("CSR["+USERNAME+"] already exists");
        }
    }

    @PreDestroy
    public void onDestroy() {
        logger.info("gracefully stop the application");
        logger.info("all controllers are stopped");
    }

    private KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private String generateEncodedCSR(KeyPair keyPair, String cn) throws OperatorCreationException, IOException {
        X500Principal subject = new X500Principal("CN=" + cn);
//        X500Principal subject = new X500Principal("O=system:nodes, CN=system:node:" + cn);
        ContentSigner signGen = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic());
        // build csr
        PKCS10CertificationRequest csr = builder.build(signGen);
        StringWriter output = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(output);
        pem.writeObject(csr);
        pem.close();
        return Base64.getEncoder().encodeToString(output.toString().getBytes());
    }

    private String generateEncodedSecretKey(Key key) throws IOException {
        StringWriter output = new StringWriter();
        JcaPEMWriter pem = new JcaPEMWriter(output);
        pem.writeObject(key);
        pem.close();
        return Base64.getEncoder().encodeToString(output.toString().getBytes());
    }
}
