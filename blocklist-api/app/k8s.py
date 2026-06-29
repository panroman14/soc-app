"""Thin wrapper over the Kubernetes API for ConfigMap read/patch.

Uses in-cluster config (mounted ServiceAccount token). RBAC is scoped to
get/update on exactly the two ConfigMaps we manage (see deploy/k8s/rbac.yaml).
"""
from kubernetes import client, config as kcfg
from kubernetes.client.rest import ApiException

_core = None


def _api():
    global _core
    if _core is None:
        try:
            kcfg.load_incluster_config()
        except Exception:
            kcfg.load_kube_config()  # local dev fallback
        _core = client.CoreV1Api()
    return _core


def get_cm_data(ns, name):
    """Return the .data dict of a ConfigMap (empty dict if it has none)."""
    cm = _api().read_namespaced_config_map(name, ns)
    return dict(cm.data or {})


def get_or_create_cm_data(ns, name, initial):
    """Like get_cm_data, but create the ConfigMap with `initial` data if absent.

    Used for the denylist store so the Helm chart doesn't have to manage (and
    accidentally reset on upgrade) its data.
    """
    try:
        return get_cm_data(ns, name)
    except ApiException as e:
        if e.status != 404:
            raise
        body = client.V1ConfigMap(
            metadata=client.V1ObjectMeta(name=name, namespace=ns), data=dict(initial))
        _api().create_namespaced_config_map(ns, body)
        return dict(initial)


def patch_cm_data(ns, name, data):
    """Strategic-merge patch only the given data keys (other keys untouched)."""
    try:
        _api().patch_namespaced_config_map(name, ns, {"data": data})
    except ApiException as e:
        raise RuntimeError("patch %s/%s failed: %s" % (ns, name, e.reason or e.status))
