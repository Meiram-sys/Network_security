import pandas as pd
import joblib

def main():
    base = '/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/artifacts/'
    csv_path = '/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/src/parser/network_data/real_packet_features.csv'  # <-- Define your CSV path here

    # Load model and label encoder
    model = joblib.load(base + 'lightgbm_network_traffic_model.joblib')
    label_encoder = joblib.load(base + 'label_encoder.joblib')

    # Load data
    data = pd.read_csv(csv_path)
    data.columns = data.columns.str.replace(' ', '_')

    # Prepare features (drop Label if exists)
    X = data.drop(columns=['Label'], errors='ignore')

    # Predict and decode labels
    preds_encoded = model.predict(X)
    preds_decoded = label_encoder.inverse_transform(preds_encoded)

    # Add predictions to dataframe and print
    data['Predicted_Label'] = preds_decoded
    data.to_csv("/Users/meiramzarypkanov/Desktop/University/4_Network_Security/Network_security/NetworkSecurity/model_result/result.csv",index=False)

if __name__ == '__main__':
    main()
