import json

from app.evaluation.runner import evaluate_dataset


def main():
    report = evaluate_dataset()

    print(
        json.dumps(
            report,
            indent=4,
        )
    )


if __name__ == "__main__":
    main()
