from PySide6.QtCore import QUrl
from PySide6.QtWidgets import QApplication
from PySide6.QtWebEngineCore import QWebEngineCertificateError
from PySide6.QtWebEngineWidgets import QWebEnginePage, QWebEngineSettings, QWebEngineView

class CustomPage(QWebEnginePage):
    def certificateError(self, error):
        # Ignore certificate errors
        return True

if __name__ == "__main__":
    app = QApplication([])
    
    view = QWebEngineView()
    page = CustomPage()
    view.setPage(page)
    
    # Disable SSL certificate verification
    settings = view.settings()
    settings.setAttribute(QWebEngineSettings.ErrorPageEnabled, False)
    settings.setAttribute(QWebEngineSettings.WebAttribute.SslErrorOverrideEnabled, True)

    view.setUrl(QUrl("https://example.com"))
    view.show()

    app.exec()
