import json
import os
from datetime import datetime


def save_json_report(data, output_path):
    """Save analysis results as a JSON report."""

    directory = os.path.dirname(output_path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

    return output_path


def save_markdown_report(data, output_path):
    """Save analysis results as a Markdown report."""

    directory = os.path.dirname(output_path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write("# RECONX Security Analysis\n\n")

        file.write(
            f"**Generated:** "
            f"{datetime.now().isoformat(timespec='seconds')}\n\n"
        )

        file.write("## File\n\n")
        file.write(f"- **Path:** `{data['file']}`\n")
        file.write(f"- **Type:** {data['type']}\n")
        file.write(f"- **Size:** {data['size']} bytes\n")
        file.write(f"- **Entropy:** {data['entropy']:.2f}\n")

        file.write("\n## Hashes\n\n")
        file.write(f"- **MD5:** `{data['md5']}`\n")
        file.write(f"- **SHA-256:** `{data['sha256']}`\n")

        file.write("\n## Indicators\n\n")

        if data["indicators"]:
            for indicator in data["indicators"]:
                file.write(f"- ⚠️ {indicator}\n")
        else:
            file.write("- No basic suspicious indicators detected.\n")

        file.write("\n## URLs\n\n")

        if data["urls"]:
            for url in data["urls"]:
                file.write(f"- `{url}`\n")
        else:
            file.write("- No URLs detected.\n")

        file.write("\n## Risk Assessment\n\n")
        file.write(f"- **Score:** {data['risk_score']}/100\n")
        file.write(f"- **Assessment:** {data['risk_label']}\n")

        file.write(
            "\n> Static analysis only. "
            "The analyzed file was not executed.\n"
        )

    return output_path
