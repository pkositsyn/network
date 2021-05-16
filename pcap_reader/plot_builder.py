import matplotlib.pyplot as plt
import typing as tp


def build_and_save_plot(filename: str, data: tp.List[float], name: str, from_addr: str, to_addr: str):
    plt.figure()
    plt.title(f"{name} - from {from_addr} to {to_addr}")
    plt.xlabel("time in seconds")
    plt.ylabel("percent")
    plt.plot(data)
    plt.savefig(filename)
