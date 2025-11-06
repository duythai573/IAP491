# Dockerfile cho ứng dụng web Node.js - Quản lý sinh viên
# Mục đích: Deploy một REST API quản lý thông tin sinh viên

# Lỗi 1: Sử dụng latest tag thay vì version cụ thể
FROM node:latest
LABEL maintainer="test@example.com"

WORKDIR app
# Lỗi 2: Cài thêm packages với apt-get mà không clean cache
RUN apt-get update && apt-get install -y curl wget git

# Copy toàn bộ trước khi install (không tối ưu cache)
COPY . .

# Lỗi 3: Không clean npm cache
RUN npm install

# Cấu hình database (Lỗi 4: Hardcode credentials)
ENV DB_HOST=localhost
ENV DB_USER=admin
ENV DB_PASSWORD=admin123456
ENV JWT_SECRET=my-secret-key-2024
ENV API_KEY=sk-1234567890abcdef

# Lỗi 5: Expose nhiều ports không cần thiết
EXPOSE 3000
EXPOSE 22
EXPOSE 9229

# Lỗi 6: Không có HEALTHCHECK để monitor container

# Lỗi 7: Không tạo non-root user (chạy với root - nguy hiểm!)

# Lỗi 8: Sử dụng shell form thay vì exec form
CMD npm start
