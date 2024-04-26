/*
 * Copyright (c) 2024 Huawei Technologies Co., Ltd.
 * openFuyao is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

// Package templates
package templates

// DefaultLoginTemplateString the sample login page html
const (
	DefaultLoginTemplateString = `<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css">
    <script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js"></script>
    <script src="//code.jquery.com/jquery-2.2.4.min.js"></script>
</head>

<body>
<div class="container">
    <h1>Login In</h1>
    <form action="{{.Action}}" method="POST">
        <div class="form-group">
            <label for="username">OpenFuyao User</label>
            <input type="text" class="form-control" name="username" required placeholder="Enter username">
        </div>
        <div class="form-group">
            <label for="password">Password</label>
            <input type="password" class="form-control" name="password" required placeholder="Enter password">
        </div>
        <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
        <input type="hidden" name="then" value="{{.Then}}">
        <button type="submit" class="btn btn-success">Login</button>
    </form>
</div>
</body>

</html>`
)
