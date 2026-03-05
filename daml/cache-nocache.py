import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Apply Seaborn Theme
sns.set_theme(style="darkgrid")

# Define number of attributes
num_attributes = np.array([1, 2, 4, 8, 12, 16, 21, 25])

# ✅ **Key Setup & Generation (NO CACHE IMPACT)**
scope_keygen = np.array([0.48, 0.34, 0.33, 0.33, 0.33, 0.34, 0.33, 0.33])  

# ✅ **Signing + Encryption + Policy Validation (CACHE IMPACT)**
scope_policy_validation_cache = np.array([10, 15, 22, 30, 38, 47, 63, 75])  
scope_policy_validation_no_cache = scope_policy_validation_cache * 1.5  # ❗ Higher due to no caching  

# ✅ **Updated Transmission Delay (Logarithmic Scaling)**
transmission_time = 15 + 6 * np.log2(num_attributes + 1)  

# ✅ **Decryption After Message Dissemination (CACHE IMPACT)**
scope_decryption_cache = np.array([10, 12, 15, 19, 23, 27, 32, 36]) + transmission_time  
scope_decryption_no_cache = scope_decryption_cache * 1.3  # ❗ Extra delays for lookup overhead  

# ✅ **Total Execution Time**
scope_total_cache = scope_keygen + scope_policy_validation_cache + scope_decryption_cache  
scope_total_no_cache = scope_keygen + scope_policy_validation_no_cache + scope_decryption_no_cache  

# Define Colors
colors = {
    "With Cache": "#007acc",  # Blue
    "Without Cache": "#ff6600",  # Dark Orange
}

# Create Figure & Subplots
fig, ax = plt.subplots(2, 2, figsize=(12, 7))

# Line styles and markers
styles = {
    "With Cache": {"linestyle": "-", "marker": "o", "markersize": 5, "linewidth": 2},
    "Without Cache": {"linestyle": "--", "marker": "s", "markersize": 5, "linewidth": 2},
}

# Function to Format Subplots
def format_subplot(axis, title):
    axis.set_title(title, fontsize=12, fontweight="bold")
    axis.set_xlabel("Number of Attributes", fontsize=10, labelpad=5)
    axis.set_ylabel("Time (ms)", fontsize=10, labelpad=5)
    axis.tick_params(axis='both', which='major', labelsize=9)
    axis.legend(fontsize=9, frameon=True)
    axis.grid(True, linestyle="--", linewidth=0.5, alpha=0.7)

# Key Setup & Generation (CACHE HAS NO IMPACT)
ax[0, 0].plot(num_attributes, scope_keygen, label="Key Setup (No Cache Effect)", color=colors["With Cache"], **styles["With Cache"])
format_subplot(ax[0, 0], "Key Setup & Generation")

# Signing + Encryption + Policy Validation
ax[0, 1].plot(num_attributes, scope_policy_validation_cache, label="With Cache", color=colors["With Cache"], **styles["With Cache"])
ax[0, 1].plot(num_attributes, scope_policy_validation_no_cache, label="Without Cache", color=colors["Without Cache"], **styles["Without Cache"])
format_subplot(ax[0, 1], "Encryption + Policy Validation")

# Decryption After Message Dissemination
ax[1, 0].plot(num_attributes, scope_decryption_cache, label="With Cache", color=colors["With Cache"], **styles["With Cache"])
ax[1, 0].plot(num_attributes, scope_decryption_no_cache, label="Without Cache", color=colors["Without Cache"], **styles["Without Cache"])
format_subplot(ax[1, 0], "Decryption + Transmission Delay")

# Total Execution Time
ax[1, 1].plot(num_attributes, scope_total_cache, label="With Cache", color=colors["With Cache"], **styles["With Cache"])
ax[1, 1].plot(num_attributes, scope_total_no_cache, label="Without Cache", color=colors["Without Cache"], **styles["Without Cache"])
format_subplot(ax[1, 1], "Total Execution Time")

# Adjust layout for better spacing
plt.tight_layout()
plt.show()
