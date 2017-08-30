from app import create_app
# 这个不要修改配置 就用default
app = create_app('default')
# 启动程序
if __name__ == '__main__':
    app.run()
