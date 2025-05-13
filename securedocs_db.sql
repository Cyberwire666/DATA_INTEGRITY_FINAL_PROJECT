-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 13, 2025 at 02:43 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `securedocs_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `documents`
--

CREATE TABLE `documents` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `original_filename` varchar(255) DEFAULT NULL,
  `upload_time` timestamp NOT NULL DEFAULT current_timestamp(),
  `file_hash` varchar(255) DEFAULT NULL,
  `signature` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `documents`
--

INSERT INTO `documents` (`id`, `user_id`, `filename`, `original_filename`, `upload_time`, `file_hash`, `signature`) VALUES
(1, 5, 'shadwa_data_int_text.txt.enc', 'data_int_text.txt', '2025-05-12 16:28:57', '1f6c7076d3edd1e077407bc33e9c5357302e3bf9eb1015b519bb2fe24dcedb45', NULL),
(2, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 16:42:15', '37c6d8d0c05c0575f13cc7c50d84788b4285e00b13de3209502f1047c2d3e02d', NULL),
(3, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 22:50:57', '37c6d8d0c05c0575f13cc7c50d84788b4285e00b13de3209502f1047c2d3e02d', NULL),
(4, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 22:51:04', '37c6d8d0c05c0575f13cc7c50d84788b4285e00b13de3209502f1047c2d3e02d', NULL),
(5, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 22:52:18', '37c6d8d0c05c0575f13cc7c50d84788b4285e00b13de3209502f1047c2d3e02d', NULL),
(6, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 22:52:47', '3346d5ae64c8aeb3029e7260bbf624fe1a9b7c8fb23c06d6fc7f2f76f4d8e176', NULL),
(7, 5, 'shadwa_second_test.txt.enc', 'second_test.txt', '2025-05-12 22:52:57', '3346d5ae64c8aeb3029e7260bbf624fe1a9b7c8fb23c06d6fc7f2f76f4d8e176', NULL),
(8, 5, 'shadwa_PRE_FINAL_TEST.txt.enc', 'PRE_FINAL_TEST.txt', '2025-05-12 23:12:55', '0ffcc0818349249b1cde2713736af0c2335ea1851bb510d828c9fd425d9e45c0', NULL),
(9, 5, 'shadwa_PRE_FINAL_TEST.txt.enc', 'PRE_FINAL_TEST.txt', '2025-05-12 23:14:06', '0ffcc0818349249b1cde2713736af0c2335ea1851bb510d828c9fd425d9e45c0', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE `logs` (
  `id` int(11) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `action_type` varchar(100) DEFAULT NULL,
  `message` text DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('admin','user') DEFAULT 'user',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `2fa_secret` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `role`, `created_at`, `2fa_secret`) VALUES
(5, 'shadwa', 'shadwaahmed20@yahoo.com', '$2b$12$bxS9zOXPw0EnwIX.DP3R9OB0U1Rr7MNlN4M8ieaL4BbxuW/C9zZDm', 'admin', '2025-05-12 16:14:50', NULL),
(6, 'alia', 'alia21@gmail.com', '$2b$12$5.a4.ZG5iJCjwF6L7USjD.nUZxumfyuzARJiMJueW91An/DFYq/LK', 'user', '2025-05-12 23:49:17', NULL),
(7, 'nagham', 'nagham@gmail.com', '$2b$12$lHqYYOQHfJr8XzwRs5SgUuG1kQ83FQKwFXRVoaoZRIgn8vBWkP85u', 'user', '2025-05-13 00:04:21', '7G4TE2KUNSBZF2OFP4ZFN7XMPL2SJFAH');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `documents`
--
ALTER TABLE `documents`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `logs`
--
ALTER TABLE `logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `documents`
--
ALTER TABLE `documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `logs`
--
ALTER TABLE `logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `documents`
--
ALTER TABLE `documents`
  ADD CONSTRAINT `documents_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
