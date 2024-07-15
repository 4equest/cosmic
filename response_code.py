class ResponseCode:
    """クライアント、サーバー間の通信で利用するサーバーからのレスポンスコード"""
    
    OK = 100
    ALREADY_BLOCKED = 101
    INVALID_JSON = 102
    TIMEOUT = 103
