package com.vmware.cnasg.kubeconfig.watcher;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.fabric8.kubernetes.api.model.*;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequest;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequestCondition;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequestConditionBuilder;
import io.fabric8.kubernetes.api.model.certificates.CertificateSigningRequestStatus;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.WatcherException;
import io.fabric8.kubernetes.client.internal.KubeConfigUtils;
import io.fabric8.kubernetes.client.internal.SerializationUtils;
import io.fabric8.kubernetes.client.utils.HttpClientUtils;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CertificateSigningRequestWatcher extends AbstractWatcher<CertificateSigningRequest> {

    private static final String CSR_REQUEST_TYPE = "self-service-csr-request";
    private static final String CSR_APPROVAL_MESSAGE = "Approved By Self-Service Portal Admin";
    private static final String CSR_APPROVAL_REASON = "ApprovedBySelfServicePortalAdmin";
    private static final String CSR_APPROVAL_TYPE = "Approved";

    private static final Logger logger = LoggerFactory.getLogger(CertificateSigningRequestWatcher.class);

    public CertificateSigningRequestWatcher(KubernetesClient client) {
        super(client);
    }

    @Override
    public void eventReceived(Action action, CertificateSigningRequest csr) {
        String csrName = csr.getMetadata().getName();
        logger.info("eventReceived[csr:" + csrName + ",action:" + action + "]");
        logger.info("csr.toString(): " + csr.toString());

        switch (action) {
            case ADDED:
                if (!csr.getMetadata().getAnnotations().isEmpty()
                        && csr.getMetadata().getAnnotations().get(CSR_REQUEST_TYPE) != null) {
                    CertificateSigningRequestCondition condition = new CertificateSigningRequestConditionBuilder()
                            .withMessage(CSR_APPROVAL_MESSAGE)
                            .withReason(CSR_APPROVAL_REASON)
                            .withType(CSR_APPROVAL_TYPE)
                            .build();

                    CertificateSigningRequestStatus currentStatus = csr.getStatus();
                    List<CertificateSigningRequestCondition> currentStatusConditions = currentStatus.getConditions();
                    currentStatusConditions.add(condition);

                    // subresource /approval is not available, not working at all
//                client.certificates().v1beta1().certificateSigningRequests().updateStatus(csr);

                    String approvalRequestBody = null;
                    try {
                        approvalRequestBody = SerializationUtils.dumpAsYaml(csr);
                        approveCSR(csrName,approvalRequestBody);
                    } catch (JsonProcessingException e) {
                        logger.error("error",e);
                    }

                    logger.info("url: " + client.getConfiguration().getMasterUrl());
                    logger.info("ca: " + client.getConfiguration().getCaCertData());
                    logger.info("request: " + approvalRequestBody);
                }
                break;
            case MODIFIED:
                Map<String,String> annotations = csr.getMetadata().getAnnotations();
                if (!annotations.isEmpty()
                        && annotations.get(CSR_REQUEST_TYPE) != null) {
                    List<CertificateSigningRequestCondition> conditions = csr.getStatus().getConditions();
                    if (!conditions.isEmpty()) {
                        while (conditions.iterator().hasNext()) {
                            CertificateSigningRequestCondition condition = conditions.iterator().next();
                            if (condition.getReason().equals(CSR_APPROVAL_REASON)
                                && condition.getType().equals(CSR_APPROVAL_TYPE)) {
                                String privateKey = annotations.get("private-key");
                                String clientCert = csr.getStatus().getCertificate();
                                String kubeConfigData = generateKubeConfig(privateKey,clientCert);
                                logger.info("kubeConfigData: " + kubeConfigData);
                                break;
                            }
                        }
                    }
                }
                break;
            case DELETED:
            case ERROR:
            default:
                logger.info("action: " + action);
        }

    }

    @Override
    public void onClose(WatcherException e) {

    }

    private String generateKubeConfig(String privateKey, String clientCert) {
        Cluster cluster = new ClusterBuilder()
                .withServer(client.getConfiguration().getMasterUrl())
                .withCertificateAuthorityData(client.getConfiguration().getCaCertData())
                .build();
        NamedCluster namedCluster = new NamedClusterBuilder()
                .withCluster(cluster)
                .withName("smu")
                .build();
        List<NamedCluster> namedClusters = new ArrayList<>();
        namedClusters.add(namedCluster);

        AuthInfo authInfo = new AuthInfoBuilder()
                .withClientCertificateData(clientCert)
                .withClientKeyData(privateKey)
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

        io.fabric8.kubernetes.api.model.Config config = new ConfigBuilder()
                .withApiVersion("v1")
                .withKind("Config")
                .withClusters(namedClusters)
                .withContexts(namedContexts)
                .withUsers(namedAuthInfos)
                .withCurrentContext(namedContext.getName())
                .build();

        String kubeConfigData = null;
        try {
            KubeConfigUtils.persistKubeConfigIntoFile(config,"/tmp/" + namedContext.getName());
            kubeConfigData = Files.readString(Paths.get("/tmp/" + namedContext.getName()));
        } catch (IOException e) {
            logger.error("error",e);
        }
        return kubeConfigData;
    }

    private boolean approveCSR(String csrName, String yamlBody) {
        boolean success = false;
        String baseURL = client.getConfiguration().getMasterUrl();
        String uri = "/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/" + csrName + "/approval";
        OkHttpClient httpClient = HttpClientUtils.createHttpClient(client.getConfiguration());
        MediaType mediaType = MediaType.parse("application/yaml; charset=utf-8");
        RequestBody body = RequestBody.create(mediaType, yamlBody);

        Request request = new Request.Builder()
                .url(baseURL + uri)
                .put(body) //PUT
                .build();
        try {
            Response response = httpClient.newCall(request).execute();
            success = true;
        } catch (IOException e) {
            logger.error("error:", e);
        }
        return success;
    }
}
