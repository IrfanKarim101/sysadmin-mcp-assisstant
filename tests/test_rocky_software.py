import pytest

from sysadmin_mcp.rocky_software import SoftwareDenied, catalog, plan, validate_upgrade


@pytest.mark.parametrize("product", ["nginx", "tomcat", "kafka", "mysql", "mongodb"])
@pytest.mark.parametrize("deployment", ["native", "podman"])
def test_upgrade_always_protects_existing_data_before_install(product, deployment):
    result = plan(product, "upgrade", "8.0.12", deployment)
    steps = result["steps"]
    assert steps.index("verify_backup_integrity_and_restore_evidence") < steps.index("install_exact_approved_version")
    assert "initialize_new_instance" not in steps
    assert "compare_pre_and_post_upgrade_application_inventory" in steps
    assert result["preserve_data"] is True
    assert result["executable"] is False


@pytest.mark.parametrize("product", ["nginx", "tomcat", "kafka", "mysql", "mongodb"])
def test_install_refuses_existing_data(product):
    steps = plan(product, "install", "1.2.3")["steps"]
    assert steps.index("refuse_existing_installation_or_nonempty_data_paths") < steps.index("initialize_new_instance")


@pytest.mark.parametrize("current,target", [("8.0.1", "8.0.1"), ("8.0.2", "8.0.1"), ("8.0.1", "8.4.1"), ("8.0.1", "9.0.1")])
def test_downgrade_equal_and_cross_release_are_denied(current, target):
    with pytest.raises(SoftwareDenied):
        validate_upgrade(current, target)


def test_numeric_patch_upgrade():
    validate_upgrade("8.0.9", "8.0.12")


@pytest.mark.parametrize("version", ["latest", "1.2", "1.2.3;reboot", "-y", "1.2.3\n", "01.2.3"])
def test_version_is_not_a_command_or_floating_label(version):
    with pytest.raises(SoftwareDenied):
        plan("nginx", "install", version)


def test_catalog_never_claims_live_execution():
    assert len(catalog()) == 5
    assert all(not row["live_execution"] for row in catalog())


def test_unknown_product_and_action_are_denied():
    for product, action in [("shell", "install"), ("mysql", "erase")]:
        with pytest.raises(SoftwareDenied):
            plan(product, action, "1.2.3")


def test_podman_requires_digest_persistent_volumes_and_original_image():
    steps = plan("mysql", "upgrade", "8.0.42", "podman")["steps"]
    for requirement in ["verify_image_digest_and_vendor",
                        "verify_persistent_volume_mapping_and_selinux_labels",
                        "preserve_environment_secrets_and_existing_image_digest"]:
        assert steps.index(requirement) < steps.index("install_exact_approved_version")
    with pytest.raises(SoftwareDenied):
        plan("mysql", "install", "8.0.42", "shell")
