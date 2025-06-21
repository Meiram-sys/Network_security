"""
inference.py
"""
import pandas as pd
import joblib

def main():
    base = '/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/artifacts/'
    csv_path = '/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/src/parser/network_data/real_packet_features.csv'  
    
    # Load model and label encoder
    model = joblib.load(base + 'lightgbm_network_traffic_model.joblib')
    label_encoder = joblib.load(base + 'label_encoder.joblib')
    
    # Load data
    data = pd.read_csv(csv_path)
    data.columns = data.columns.str.replace(' ', '_')
    
    # Store IP addresses for later use in identifying problematic packets
    ip_info = data[['Source_IP', 'Destination_IP','Destination_Port']].copy()
    
    # Prepare features for model (exclude IPs )
    columns_to_exclude = ['Source_IP', 'Destination_IP','Destination_Port']
    X = data.drop(columns=columns_to_exclude, errors='ignore')
    
    print(f"Features used for prediction: {X.shape[1]} columns")
    print(f"Total samples: {len(X)}")
    
    # Predict and decode labels
    preds_encoded = model.predict(X)
    preds_decoded = label_encoder.inverse_transform(preds_encoded)
    
    # Create result dataframe with IP addresses and predictions
    result_df = ip_info.copy()
    result_df['Predicted_Label'] = preds_decoded
    
    # Add original features back if you want full analysis
    result_df = pd.concat([result_df, X], axis=1)
    
    # Save results
    output_path = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/model_result/result.csv"
    result_df.to_csv(output_path, index=False)
    
    # Print summary
    print("\n=== PREDICTION SUMMARY ===")
    prediction_counts = pd.Series(preds_decoded).value_counts()
    print(prediction_counts)
    
    # Show problematic packets (non-BENIGN)
    problematic = result_df[result_df['Predicted_Label'] != 'BENIGN']
    if not problematic.empty:
        print(f"\n=== PROBLEMATIC PACKETS FOUND: {len(problematic)} ===")
        print("\nSource IPs with issues:")
        print(problematic['Source_IP'].value_counts().head(10))
        print("\nDestination IPs with issues:")
        print(problematic['Destination_IP'].value_counts().head(10))
        print("\nAttack types detected:")
        print(problematic['Predicted_Label'].value_counts())
        
        # Save only problematic packets for quick analysis
        problematic_path = "/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_project/Network_security/NetworkSecurity_project/model_result/problematic_packets.csv"
        problematic.to_csv(problematic_path, index=False)
        print(f"\nProblematic packets saved to: {problematic_path}")
    else:
        print("\n✅ All traffic appears to be BENIGN")
    
    print(f"\nFull results saved to: {output_path}")
    print("DONE")

if __name__ == '__main__':
    main()