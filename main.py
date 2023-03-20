from MalWorkz.MalWorkz import MalWorkz, ActionSet


def main():
    m = MalWorkz(
        malware_path="MLSEC_2021_malware/010",
        new_pe_name="010",
        step=0.0000001,
        threshold=0.82,
        max_pe_size_bytes=2000000,
        model="ember",
        max_epochs=10000,
        virustotal_api_key=None,
        avs=['SentinelOne', 'CrowdStrike'],
        use_virustotal=False,
        action_set=[
            ActionSet.RANDOMIZE_HEADERS,
            ActionSet.ADD_SECTION,
            ActionSet.ADD_CODE_CAVE,
            ActionSet.ADD_STUB_AND_ENCRYPT_CODE,
            ActionSet.RENAME_EXISTING_SECTION,
            ActionSet.SIGN_PE,
        ],
    )
    m.generate_adversarial_pe()
    m.write()


if __name__ == "__main__":
    main()
