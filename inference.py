import pandas as pd
import re
import math
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import streamlit as st

def validate_url(url):
    # Regular expression for URL validation
    pattern = re.compile(r'^(http|https)://[a-zA-Z0-9-._~:/?#@!$&\'()*+,;=%]+$')
    return re.match(pattern, url)

st.title("Malware Detection Tool")
st.write("This tool detects if a URL is malicious or not using a self designed RNN model.")
col1 , col2 = st.columns(2)
with col1:
    url = st.text_input("Enter the URL")
    data = {'url' : url}
    df = pd.DataFrame(data,index=[0])
    if url:
        if validate_url(url):
            with st.status('Checking'):

                def calculate_entropy(url):
                    # Count frequency of each character in the URL
                    freq = {}
                    for char in url:
                        freq[char] = freq.get(char, 0) + 1

                    # Calculate entropy
                    entropy = 0
                    length = len(url)
                    for count in freq.values():
                        probability = count / length
                        entropy -= probability * math.log2(probability)

                    return entropy


                def tokenize_url(url):
                    return [ord(char) for char in url]


                def extract_features(df):
                    # URL length
                    df['url_length'] = df['url'].apply(lambda x: len(x))

                    # Count special characters in URL
                    df['special_char_count'] = df['url'].apply(lambda x: len(re.findall(r'[?&=]', x)))

                    # Count number of subdomains
                    df['subdomain_count'] = df['url'].apply(lambda x: len(x.split('.')) - 2)

                    # Check if an IP address is present in the URL
                    df['has_ip'] = df['url'].apply(lambda x: 1 if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', x) else 0)
                    
                    # Calculate entropy of the URL
                    df['entropy'] = df['url'].apply(calculate_entropy)

                    # Check if the URL contains a suspicious name
                    suspicious_names = ['confirm', 'account', 'secure', 'banking', 'secure', 'login', 'signin', 'update', 'password', 'verify','free','game','win','click','prize','cash','money','offer','discount','deal','sale','cheap','best','top','amazing','new','hot','popular','trending','sensational','latest','exclusive','limited','urgent','important','breaking','alert','warning','emergency','crisis','critical','fatal','vital','immediate','important','essential','key','necessary','required','compulsory','mandatory','obligatory','pressing','acute','burning','paramount','preeminent','urgent','top-priority','high-priority','crucial']
                    df['has_suspicious_name'] = df['url'].apply(lambda x: 1 if any(name in x for name in suspicious_names) else 0)
                    
                    # Apply tokenization
                    df['tokenized_url'] = df['url'].apply(tokenize_url)
                    
                    return df

                df = extract_features(df)
                
                class RNNClassifier(nn.Module):
                    def __init__(self, input_dim, hidden_dim, output_dim, additional_feature_dim):
                        super(RNNClassifier, self).__init__()
                        self.rnn = nn.LSTM(input_dim, hidden_dim, batch_first=True)
                        self.fc1 = nn.Linear(hidden_dim + additional_feature_dim, 128) 
                        self.fc2 = nn.Linear(128, output_dim)
                    
                    def forward(self, rnn_input, additional_features):
                        h, _ = self.rnn(rnn_input)
                        h = h[:, -1, :]  
                        
        
                        combined_input = torch.cat((h, additional_features), dim=1)
                        
                        
                        x = torch.relu(self.fc1(combined_input))
                        out = torch.sigmoid(self.fc2(x))
                        return out

                
                input_dim = 1  
                hidden_dim = 64
                output_dim = 1  
                additional_feature_dim = 5  

                model = RNNClassifier(input_dim, hidden_dim, output_dim, additional_feature_dim)

                # Load the saved model state
                model.load_state_dict(torch.load('model.pth'))

                # Set the model to evaluation mode
                model.eval()

                max_len = 50
                # Pad sequences manually
                def pad_sequences_torch(sequences, max_len):
                    padded_sequences = torch.zeros((len(sequences), max_len), dtype=torch.float32)
                    for i, seq in enumerate(sequences):
                        seq_len = min(len(seq), max_len)
                        padded_sequences[i, :seq_len] = torch.tensor(seq[:seq_len], dtype=torch.float32)
                    return padded_sequences

                
                rnn_data = pad_sequences_torch(df['tokenized_url'], max_len)  
                additional_data = df[['special_char_count', 'subdomain_count', 'has_ip', 'entropy', 'has_suspicious_name']].values

                
                rnn_data = torch.tensor(rnn_data, dtype=torch.float32)
                additional_data = torch.tensor(additional_data, dtype=torch.float32)

                
                rnn_data = rnn_data.unsqueeze(-1)  

                
                with torch.no_grad(): 
                    prediction = model(rnn_data, additional_data)
                    predicted_label = (prediction > 0.5).int()  

            if predicted_label == 1:
                st.write("The URL is malicious")
            else:
                st.write("The URL is safe")
        else:
            st.error("Invalid URL format. Please enter a valid URL starting with http:// or https://.")


            
