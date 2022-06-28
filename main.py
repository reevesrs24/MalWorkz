from MalWorkz import MalWorkz


def main():
    m = MalWorkz(
        path="MLSEC_2021_malware/001",
        pe_name="new.exe",
        code_cave_size=512,
        step=0.00001,
        threshold=0.82,
        model="ember"
    )
    m.generate_adversarial_pe()


if __name__ == "__main__":
    main()
