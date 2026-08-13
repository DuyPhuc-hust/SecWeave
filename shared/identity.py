from shared.models.entities import Authorization


def get_execution_identity(authorization: Authorization) -> str:
    """Identity Service (khung) — weekly plan W5: identity dùng để thực thi
    hành động CHỈ được lấy từ Authorization đã nạp qua Gate 2 — không có
    đường nào trong code này đọc biến môi trường hay config cá nhân của
    người vận hành để dùng thay thế.

    Đây là điểm truy cập DUY NHẤT cho identity thực thi trong toàn bộ
    codebase — mọi nơi cần identity để thực thi hành động phải gọi qua đây,
    không tự đọc os.environ hay config cá nhân ở nơi khác.
    """
    if not authorization.identity:
        raise ValueError(
            "Authorization chưa có identity nào được cấp qua Gate 2 — không có "
            "identity cá nhân nào được dùng thay thế khi thiếu."
        )
    return authorization.identity
