from app.config import Settings


def test_nuclei_binary_has_governed_default():
    field = Settings.model_fields[
        "nuclei_binary"
    ]

    assert field.default == (
        "/usr/local/bin/pd-nuclei"
    )


def test_nuclei_template_root_has_immutable_default():
    field = Settings.model_fields[
        "nuclei_template_root"
    ]

    assert field.default == (
        "/opt/nuclei-templates"
    )


def test_nuclei_output_budget_has_safe_default():
    field = Settings.model_fields[
        "nuclei_max_output_bytes"
    ]

    assert field.default == 10_000_000


def test_nuclei_runtime_settings_can_be_overridden(
    monkeypatch,
):
    monkeypatch.setenv(
        "NUCLEI_BINARY",
        "/custom/pd-nuclei",
    )

    monkeypatch.setenv(
        "NUCLEI_TEMPLATE_ROOT",
        "/custom/templates",
    )

    monkeypatch.setenv(
        "NUCLEI_MAX_OUTPUT_BYTES",
        "123456",
    )

    settings = Settings()

    assert settings.nuclei_binary == (
        "/custom/pd-nuclei"
    )

    assert settings.nuclei_template_root == (
        "/custom/templates"
    )

    assert (
        settings.nuclei_max_output_bytes
        == 123456
    )
