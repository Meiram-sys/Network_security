import pandas as pd
import os
import glob


def read_all_csv_files(directory_path):
    """
    Read all CSV files from a directory into a single DataFrame.
    
    Args:
        directory_path: Path to the directory containing CSV files
    Returns:
        Combined DataFrame containing data from all CSV files
    """
    # Check if directory exists
    if not os.path.exists(directory_path):
        raise FileNotFoundError(f"Directory not found: {directory_path}")
    
    # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory_path, "*.csv"))
    if not csv_files:
        print(f"No CSV files found in {directory_path}")
        return None
    
    # Create an empty list to store individual DataFrames
    dfs = []
    
    # Read each CSV file and append to the list
    for file in csv_files:
        try:
            df = pd.read_csv(file)
            dfs.append(df)
            print(f"Successfully read: {os.path.basename(file)}")
        except Exception as e:
            print(f"Error reading {os.path.basename(file)}: {str(e)}")
    
    if not dfs:
        print("No valid CSV files were read.")
        return None
    
    # Combine all DataFrames into one
    combined_df = pd.concat(dfs, ignore_index=True)
    print(f"Combined {len(dfs)} CSV files. Total rows: {len(combined_df)}")
    return combined_df


if __name__ == "__main__":
    # Usage
    directory_path = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/data/MachineLearningCVE"
    mlcve = read_all_csv_files(directory_path)
    
    if mlcve is not None:
        mlcve = mlcve.dropna()
        mlcve.columns = mlcve.columns.str.strip()
        
        print("Unique labels in the dataset:")
        unique_labels = mlcve['Label'].unique()
        print(unique_labels)
        print(f"Total number of unique labels: {mlcve['Label'].nunique()}")
        
        mlcve.to_csv("/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/data/ModelData/features.csv", index=False)