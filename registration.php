<?php
include_once('includes/config.php');

if (isset($_POST['submit'])) {
    $fname = trim($_POST['fname']);
    $lname = trim($_POST['lname']);
    $emailid = trim($_POST['emailid']);
    $mobileno = trim($_POST['mobileno']);
    $password = $_POST['newpassword'];

    // Basic server-side validation
    if (!filter_var($emailid, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email format'); window.location.href='registration.php';</script>";
        exit;
    }

    if (!preg_match('/^[0-9]{10}$/', $mobileno)) {
        echo "<script>alert('Mobile number must be 10 digits'); window.location.href='registration.php';</script>";
        exit;
    }

    if (strlen($password) < 8) {
        echo "<script>alert('Password must be at least 8 characters long'); window.location.href='registration.php';</script>";
        exit;
    }

    // Check if email or mobile already exists
    $stmt = mysqli_prepare($con, "SELECT id FROM tblregistration WHERE emailId = ? OR mobileNumber = ?");
    mysqli_stmt_bind_param($stmt, "ss", $emailid, $mobileno);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    $count = mysqli_stmt_num_rows($stmt);
    mysqli_stmt_close($stmt);

    if ($count == 0) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = mysqli_prepare($con, "INSERT INTO tblregistration (firstName, lastName, emailId, mobileNumber, userPassword) VALUES (?, ?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, "sssss", $fname, $lname, $emailid, $mobileno, $hashedPassword);
        $success = mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);

        if ($success) {
            echo "<script>alert('Registration successful. Please login now'); window.location.href='login.php';</script>";
        } else {
            echo "<script>alert('Something went wrong. Please try again'); window.location.href='registration.php';</script>";
        }
    } else {
        echo "<script>alert('Email ID or Mobile Number already registered.'); window.location.href='registration.php';</script>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <title>e-Diary Management System | Register</title>
    <link href="css/styles.css" rel="stylesheet" />
    <script src="https://use.fontawesome.com/releases/v6.1.0/js/all.js" crossorigin="anonymous"></script>
    <script type="text/javascript">
        function valid() {
            if (document.registration.newpassword.value !== document.registration.confirmpassword.value) {
                alert("Password and Confirm Password do not match!");
                document.registration.confirmpassword.focus();
                return false;
            }
            return true;
        }
    </script>
</head>

<body class="bg-primary">
    <div id="layoutAuthentication">
        <div id="layoutAuthentication_content">
            <main>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-lg-7">
                            <div class="card shadow-lg border-0 rounded-lg mt-5">
                                <div class="card-header">
                                    <h3 class="text-center font-weight-light my-4">e-Diary Management System</h3>
                                </div>
                                <h3 class="text-center font-weight-light my-4">User Registration</h3>
                                <div class="card-body">
                                    <form method="post" name="registration" onSubmit="return valid();">
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <div class="form-floating mb-3 mb-md-0">
                                                    <input class="form-control" id="inputFirstName" type="text" name="fname" placeholder="Enter your first name" required />
                                                    <label for="inputFirstName">First name</label>
                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div class="form-floating">
                                                    <input class="form-control" id="inputLastName" type="text" name="lname" placeholder="Enter your last name" required />
                                                    <label for="inputLastName">Last name</label>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="inputEmail" type="email" name="emailid" placeholder="name@example.com" required />
                                            <label for="inputEmail">Email address</label>
                                        </div>
                                        <div class="form-floating mb-3">
                                            <input class="form-control" id="inputMobile" type="text" name="mobileno" placeholder="Enter your mobile number" maxlength="10" pattern="[0-9]{10}" required />
                                            <label for="inputMobile">Mobile Number</label>
                                        </div>
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <div class="form-floating mb-3 mb-md-0">
                                                    <input class="form-control" id="newpassword" type="password" name="newpassword" placeholder="Create a password" required />
                                                    <label for="newpassword">Password</label>
                                                </div>
                                            </div>
                                            <div class="col-md-6">
                                                <div class="form-floating mb-3 mb-md-0">
                                                    <input class="form-control" id="confirmpassword" type="password" name="confirmpassword" placeholder="Confirm password" required />
                                                    <label for="confirmpassword">Confirm Password</label>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="mt-4 mb-0">
                                            <div class="d-grid">
                                                <button type="submit" name="submit" class="btn btn-primary btn-block">Create Account</button>
                                            </div>
                                        </div>
                                    </form>
                                </div>
                                <div class="card-footer text-center py-3">
                                    <div class="small"><a href="login.php">Have an account? Go to login</a></div>
                                    <hr />
                                    <div class="small"><a href="index.php">Back to Home Page</a></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
        <?php include_once('includes/footer.php'); ?>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" crossorigin="anonymous"></script>
    <script src="js/scripts.js"></script>
</body>

</html>