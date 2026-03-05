import pandas as pd
import matplotlib.pyplot as plt

# Load the CSV file
df = pd.read_csv("results.csv")

# Define graph parameters
metrics = ["keygen_time_ms", "signcryption_time_ms", "validation_time_ms", "transmission_time_ms", "designcryption_time_ms", "total_time_ms"]
titles = ["Key Generation", "Signcryption", "Validation", "Transmission", "DeSigncryption", "Total Execution Time"]

# Generate bar charts for each metric
for i, metric in enumerate(metrics):
    plt.figure(figsize=(8, 5))
    plt.bar(df["num_attributes"], df[metric], color=['blue', 'orange', 'green', 'red', 'purple', 'brown'])
    plt.xlabel("Number of Attributes")
    plt.ylabel("Time (ms)")
    plt.title(f"Performance Analysis: {titles[i]} vs. Number of Attributes")
    plt.grid(axis='y')
    plt.xticks(df["num_attributes"])
    plt.show()
