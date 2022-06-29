from MalWorkz.MalWorkz import MalWorkz, ActionSet


def main():
    m = MalWorkz(
        malware_path="malware/malware.exe",
        new_pe_name="new.exe",
        step=0.00001,
        threshold=0.82,
        model="ember",
        max_epochs=10000,
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


if __name__ == "__main__":
    main()
