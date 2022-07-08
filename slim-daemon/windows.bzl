load("@io_bazel_rules_docker//container:container.bzl", "container_image", "container_push")

def windows_docker_push(base_version):
    #  Due to THIRD_PARTY_NOTICES this will fail outside of louhi environment,
    #  as THIRD_PARTY_NOTICES directory is not present locally.
    #  In order to run build locally remove THIRD_PARTY_NOTICES.
    container_image(
        name = "cilium-win-%s-image" % (base_version),
        base = ":servercore_%s" % (base_version),
        cmd = ["c:\\anet-agent.exe"],
        files = [":anet-agent.exe", "THIRD_PARTY_NOTICES"],
        operating_system = "windows",
        workdir = "c:\\",
        tags = ["manual"],
    )
    container_push(
        name = "cilium-win-%s" % (base_version),
        image = "cilium-win-%s-image" % (base_version),
        format = "Docker",
        registry = "gcr.io",
        repository = "$(PROJECT_ID)/cilium/cilium-win-%s" % (base_version),
        tag = "$(TAG)",
    )
