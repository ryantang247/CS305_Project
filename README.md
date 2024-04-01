# CS305 Computer Networks Project: HTTP File Manager

## Overview
This project entails constructing a simple file manager server in Python, adhering to the characteristics of HTTP/1.1. The server should facilitate multiple clients with legitimate permissions to view, download, upload, and delete files. Key components include building a custom HTTP server framework using the Socket API, implementing required service functions, and mapping HTTP requests to corresponding server functions accurately.

## Requirements
- Implement a server-side HTTP file manager using Python.
- Provide service APIs for clients to perform actions such as viewing directories, downloading files, uploading files, and deleting files.
- Construct the HTTP server based on TCP socket, adhering to HTTP/1.1 specifications.
- Ensure proper handling of requests, responses, status codes, headers, and response bodies.
- Support persistent connections, authorization, cookies, and chunked transfer encoding.
- Test the server functionality through accessing the provided HTTP service APIs.

## Basic Part 
- **Basic HTTP Server**: Construct a custom HTTP server using the Socket API to handle incoming HTTP requests.
- **Persistent Connection**: Implement persistent connections by default, allowing multiple requests sequentially in a single connection.
- **Support Many Clients**: Enable the server to handle multiple requests from different clients simultaneously.
- **Authorization**: Implement HTTP Basic Authorization Scheme for user authentication.

## View and Download 
- Implement directory viewing and file downloading services with authorization.
- Handle requests from clients to view files or directories and download files.
- Ensure proper handling of invalid requests and return correct status codes.

## Upload and Delete
- **Upload**: Allow users to upload files to their respective directories with authorization.
- **Delete**: Implement file deletion service with proper authorization and permission handling.

## Cookies and Session
- Provide session management using HTTP cookies.
- Generate and manage session IDs for users to maintain login status.

## Chunked Transfer 
- Implement chunked transfer encoding for streaming data transfer of large files.
- Support chunked transfer under the view and download API.

