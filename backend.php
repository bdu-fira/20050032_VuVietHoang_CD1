<?php
<?php
// api.php
require 'config.php';
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$action = $_GET['action'] ?? '';
$headers = getallheaders();

function getUserFromToken($headers) {
    global $secret_key;
    if (!isset($headers['Authorization'])) return null;
    if (!preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) return null;
    try {
        $decoded = JWT::decode($matches[1], new Key($secret_key, 'HS256'));
        return $decoded;
    } catch (Exception $e) {
        echo json_encode(["status" => "unauthorized", "message" => $e->getMessage()]);
        return null;
    }
}

function respondWithError($message) {
    echo json_encode(["status" => "error", "message" => $message]);
    exit;
}

if ($action == 'register') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['username'], $data['password'], $data['email'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $username = $data['username'];
    $password = password_hash($data['password'], PASSWORD_DEFAULT);
    $email = $data['email'];

    $stmt = $conn->prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $password, $email);
    if ($stmt->execute()) {
        echo json_encode(["status" => "success"]);
    } else {
        respondWithError($stmt->error);
    }

} elseif ($action == 'login') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['username'], $data['password'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $username = $data['username'];
    $password = $data['password'];

    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($user = $result->fetch_assoc()) {
        if (password_verify($password, $user['password'])) {
            $payload = [
                'user_id' => $user['id'],
                'username' => $user['username'],
                'role' => $user['role'],
                'exp' => time() + 3600
            ];
            $jwt = JWT::encode($payload, $secret_key, 'HS256');
            echo json_encode(["status" => "success", "token" => $jwt, "role" => $user['role']]);
        } else {
            respondWithError("Sai mật khẩu");
        }
    } else {
        respondWithError("Không tìm thấy người dùng");
    }

} elseif ($action == 'products') {
    $user = getUserFromToken($headers);
    if (!$user) respondWithError("Unauthorized");

    $res = $conn->query("SELECT * FROM products");
    echo json_encode($res->fetch_all(MYSQLI_ASSOC));

} elseif ($action == 'add_product') {
    $user = getUserFromToken($headers);
    if (!$user || $user->role !== 'admin') respondWithError("Unauthorized");

    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['name'], $data['brand'], $data['price'], $data['image'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $stmt = $conn->prepare("INSERT INTO products (name, brand, price, image) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssds", $data['name'], $data['brand'], $data['price'], $data['image']);
    echo json_encode(["status" => $stmt->execute() ? "success" : "error"]);

} elseif ($action == 'update_product') {
    $user = getUserFromToken($headers);
    if (!$user || $user->role !== 'admin') respondWithError("Unauthorized");

    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['id'], $data['name'], $data['brand'], $data['price'], $data['image'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $stmt = $conn->prepare("UPDATE products SET name=?, brand=?, price=?, image=? WHERE id=?");
    $stmt->bind_param("ssdsi", $data['name'], $data['brand'], $data['price'], $data['image'], $data['id']);
    echo json_encode(["status" => $stmt->execute() ? "success" : "error"]);

} elseif ($action == 'delete_product') {
    $user = getUserFromToken($headers);
    if (!$user || $user->role !== 'admin') respondWithError("Unauthorized");

    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['id'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
    $stmt->bind_param("i", $data['id']);
    echo json_encode(["status" => $stmt->execute() ? "success" : "error"]);

} elseif ($action == 'contact') {
    $data = json_decode(file_get_contents('php://input'), true);
    if (!$data || !isset($data['name'], $data['email'], $data['message'])) {
        respondWithError("Dữ liệu không hợp lệ");
    }

    $stmt = $conn->prepare("INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $data['name'], $data['email'], $data['message']);
    $stmt->execute();

    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = getenv('SMTP_USERNAME'); // Use environment variables
        $mail->Password = getenv('SMTP_PASSWORD'); // Use environment variables
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;

        $mail->setFrom(getenv('SMTP_USERNAME'), 'Hệ thống bán xe');
        $mail->addAddress($data['email']);
        $mail->Subject = 'Xác nhận liên hệ';
        $mail->Body    = "Chúng tôi đã nhận được tin nhắn của bạn.";
        $mail->send();
    } catch (Exception $e) {
        respondWithError("Không thể gửi email: " . $mail->ErrorInfo);
    }

    echo json_encode(["status" => "success"]);
} else {
    echo json_encode(["message" => "API không hợp lệ"]);
}
?>