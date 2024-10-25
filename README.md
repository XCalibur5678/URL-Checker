---

# Malware Detection Tool

This is a lightweight, URL-based malware detection tool built using **Streamlit**. It allows users to input URLs and to check if the URL are malicious, providing instant feedback in a simple, minimalistic user interface.

## Features

- **URL Validation**: Ensures the input URL is valid before checking.
- **Loading Animation**: Displays a loading indicator while the URL is being processed.
- **Real-Time Check**: URL analysis is triggered when pressing **Enter**
- **Malware Detection**: Uses a trained Reccurent Neural Network(RNN) model to classify URLs as malicious or safe.
- **Minimalist UI**: Designed with a simple interface for better user experience.
- **Efficacy**: Has an Accurracy of 92.84% 

## Getting Started
You can view and use the app from the [live link](https://malicious-url-checker.streamlit.app/)

##To use the app locally , follow this guide 

### Prerequisites

Before running the app, make sure you have the following installed:

- Python 3.8+
- Streamlit
- Pytorch
- Scikit-learn
- Pandas

You can install the required Python packages with:

```bash
pip install -r requirements.txt
```

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/xcalibur5678/URL-checker.git
   cd URL-checker
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Running the App

To start the app, use the following command:

```bash
streamlit run inference.py
```

This will open the application in your browser at `http://localhost:8501`.

### Usage

1. Enter the URL you'd like to check in the input field.
2. Press **Enter**, and the tool will validate the URL format and display if it's malicious or safe.
3. If the URL is invalid, an error message will guide you to correct it.

### Example

Here's an example of how the app works:

1. Input: `http://example.com`
2. Result: `The URL is safe.`

## Validation

- The URL validation ensures that the user enters a valid URL format (must start with `http://` or `https://`).
- If an invalid URL is entered, an error message will be displayed, prompting the user to correct the input.


## Contributing

Feel free to contribute to the project by submitting a pull request! Any suggestions to improve the functionality or UI are welcome.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---
