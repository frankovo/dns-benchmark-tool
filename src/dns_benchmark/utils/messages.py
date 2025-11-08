from colorama import Fore, Style


def info(msg: str) -> str:
    return f"{Style.BRIGHT}{Fore.CYAN}[i] {msg}{Style.RESET_ALL}"


def success(msg: str) -> str:
    return f"{Style.BRIGHT}{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}"


def positive(msg: str) -> str:
    return f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}"


def warning(msg: str) -> str:
    return f"{Style.BRIGHT}{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}"


def error(msg: str) -> str:
    return f"{Style.BRIGHT}{Fore.RED}[-] {msg}{Style.RESET_ALL}"


def summary_box(lines: list[str], max_width: int = 100) -> str:
    """Return a colored ASCII box with the given lines inside, wrapping long lines."""
    wrapped_lines = []
    for line in lines:
        while len(line) > max_width - 4:
            wrapped_lines.append(line[: max_width - 4])
            line = line[max_width - 4 :]
        wrapped_lines.append(line)

    width = max(len(line) for line in wrapped_lines) + 4
    top = f"{Fore.CYAN}{'=' * width}{Style.RESET_ALL}"
    bottom = top
    body = "\n".join(
        f"{Fore.CYAN}| {Style.RESET_ALL}{line.ljust(width - 4)}{Fore.CYAN} |{Style.RESET_ALL}"
        for line in wrapped_lines
    )
    return f"{top}\n{body}\n{bottom}"
