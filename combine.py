import pandas as pd
import os

# List of directories containing the combined CSV files
directories = [
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/Browsing',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/Chat',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/File Transfer',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/Mail',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/P2P',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/Streaming',
    '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/NonTor/VoIP',
]

# Read and combine the dataframes
dfs = []
for directory in directories:
    if os.path.exists(directory):
        # Find the combined CSV file in the directory
        csv_files = [f for f in os.listdir(directory) if f.endswith('.csv') and ('NonTor-' in f or 'Tor-' in f)]
        for file in csv_files:
            file_path = os.path.join(directory, file)
            df = pd.read_csv(file_path)
            # # Modify the label
            # if 'label' in df.columns:
            #     df['label'] = df['label'].apply(lambda x: 'NonTOR' if str(x).startswith('NonTor-') else ('TOR' if str(x).startswith('Tor-') else x))
            dfs.append(df)

# Concatenate all dataframes
if dfs:
    combined_df = pd.concat(dfs, ignore_index=True)
    # Save to a new CSV file
    output_path = '/home/zealot/ICC/Traffic Mimicry System/dataset/TOR&NonTOR/all_non-tor_traffic.csv'
    combined_df.to_csv(output_path, index=False)
    print(f"Combined CSV saved to {output_path}")
else:
    print("No CSV files found to combine.")
