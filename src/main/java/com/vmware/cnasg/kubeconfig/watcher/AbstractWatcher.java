package com.vmware.cnasg.kubeconfig.watcher;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.Watcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractWatcher<T> implements Watcher<T> {

    private static final Logger logger = LoggerFactory.getLogger(AbstractWatcher.class);
    protected KubernetesClient client;

    public AbstractWatcher(KubernetesClient client) {
        this.client = client;
    }

    @Override
    public void eventReceived(Action action, T t) {
        switch (action) {
            case ADDED:
            case MODIFIED:
            case DELETED:
            case ERROR:
            default:
                logger.info(t.getClass().getName() + " " + action + " " + t.toString());
        }
    }

}
