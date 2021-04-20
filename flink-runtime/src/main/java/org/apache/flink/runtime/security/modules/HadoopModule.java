/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.runtime.security.modules;

import org.apache.flink.annotation.VisibleForTesting;
import org.apache.flink.configuration.CoreOptions;
import org.apache.flink.runtime.security.KerberosUtils;
import org.apache.flink.runtime.security.SecurityConfiguration;
import org.apache.flink.runtime.util.HadoopUtils;
import org.apache.flink.util.Preconditions;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.Credentials;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.flink.configuration.ConfigurationUtils.splitPaths;
import static org.apache.flink.util.Preconditions.checkNotNull;
import static org.apache.flink.util.Preconditions.checkState;

/** Responsible for installing a Hadoop login user. */
public class HadoopModule implements SecurityModule {

    private static final Logger LOG = LoggerFactory.getLogger(HadoopModule.class);

    private final SecurityConfiguration securityConfig;

    private final Configuration hadoopConfiguration;

    private ScheduledFuture<?> handler;

    private ScheduledExecutorService scheduledExecutorService;

    public HadoopModule(
            SecurityConfiguration securityConfiguration, Configuration hadoopConfiguration) {
        this.securityConfig = checkNotNull(securityConfiguration);
        this.hadoopConfiguration = checkNotNull(hadoopConfiguration);
    }

    @VisibleForTesting
    public SecurityConfiguration getSecurityConfig() {
        return securityConfig;
    }

    @Override
    public void install() throws SecurityInstallException {

        UserGroupInformation.setConfiguration(hadoopConfiguration);

        UserGroupInformation loginUser;

        try {
            if (UserGroupInformation.isSecurityEnabled()
                    && !StringUtils.isBlank(securityConfig.getKeytab())
                    && !StringUtils.isBlank(securityConfig.getPrincipal())) {
                String keytabPath = (new File(securityConfig.getKeytab())).getAbsolutePath();

                UserGroupInformation.loginUserFromKeytab(securityConfig.getPrincipal(), keytabPath);

                loginUser = UserGroupInformation.getLoginUser();

                // supplement with any available tokens
                String fileLocation =
                        System.getenv(UserGroupInformation.HADOOP_TOKEN_FILE_LOCATION);
                if (fileLocation != null) {
                    Credentials credentialsFromTokenStorageFile =
                            Credentials.readTokenStorageFile(
                                    new File(fileLocation), hadoopConfiguration);

                    // if UGI uses Kerberos keytabs for login, do not load HDFS delegation token
                    // since
                    // the UGI would prefer the delegation token instead, which eventually expires
                    // and does not fallback to using Kerberos tickets
                    Credentials credentialsToBeAdded = new Credentials();
                    final Text hdfsDelegationTokenKind = new Text("HDFS_DELEGATION_TOKEN");
                    Collection<Token<? extends TokenIdentifier>> usrTok =
                            credentialsFromTokenStorageFile.getAllTokens();
                    // If UGI use keytab for login, do not load HDFS delegation token.
                    for (Token<? extends TokenIdentifier> token : usrTok) {
                        if (!token.getKind().equals(hdfsDelegationTokenKind)) {
                            final Text id = new Text(token.getIdentifier());
                            credentialsToBeAdded.addToken(id, token);
                        }
                    }

                    loginUser.addCredentials(credentialsToBeAdded);
                }

                if (!StringUtils.isBlank(securityConfig.getKeytabUpdatePath())) {
                    scheduleKeytabUpdater();
                }
            } else {
                // login with current user credentials (e.g. ticket cache, OS login)
                // note that the stored tokens are read automatically
                try {
                    // Use reflection API to get the login user object
                    // UserGroupInformation.loginUserFromSubject(null);
                    Method loginUserFromSubjectMethod =
                            UserGroupInformation.class.getMethod(
                                    "loginUserFromSubject", Subject.class);
                    loginUserFromSubjectMethod.invoke(null, (Subject) null);
                } catch (NoSuchMethodException e) {
                    LOG.warn("Could not find method implementations in the shaded jar.", e);
                } catch (InvocationTargetException e) {
                    throw e.getTargetException();
                }

                loginUser = UserGroupInformation.getLoginUser();
            }

            LOG.info("Hadoop user set to {}", loginUser);

            if (HadoopUtils.isKerberosSecurityEnabled(loginUser)) {
                boolean isCredentialsConfigured =
                        HadoopUtils.areKerberosCredentialsValid(
                                loginUser, securityConfig.useTicketCache());

                LOG.info(
                        "Kerberos security is enabled and credentials are {}.",
                        isCredentialsConfigured ? "valid" : "invalid");
            }
        } catch (Throwable ex) {
            throw new SecurityInstallException("Unable to set the Hadoop login user", ex);
        }
    }

    @Override
    public void uninstall() {
        if (handler != null) {
            handler.cancel(true);
            scheduledExecutorService.shutdown();
        }
    }

    private void scheduleKeytabUpdater() {
        scheduledExecutorService =
                Executors.newSingleThreadScheduledExecutor(
                        r -> {
                            Thread t = new Thread(r);
                            t.setName("Keytab-Updater");
                            return t;
                        });

        long interval = securityConfig.getKeytabUpdateInterval();
        KeytabUpdater keytabUpdater = new KeytabUpdater(securityConfig, hadoopConfiguration);
        handler =
                scheduledExecutorService.scheduleAtFixedRate(
                        keytabUpdater, interval, interval, TimeUnit.MILLISECONDS);
    }

    @VisibleForTesting
    static class KeytabUpdater implements Runnable {

        private final SecurityConfiguration securityConfig;

        private final Configuration hadoopConfig;

        private final String workingDir;

        private static Path localKeytabDir;

        public KeytabUpdater(SecurityConfiguration securityConfig, Configuration hadoopConfig) {
            this.securityConfig = securityConfig;
            this.hadoopConfig = hadoopConfig;
            String[] dirs =
                    splitPaths(securityConfig.getFlinkConfig().getString(CoreOptions.TMP_DIRS));
            // should be at least one directory.
            checkState(dirs.length > 0);
            this.workingDir = dirs[0];
        }

        private static void createLocalKeytabDirIfNotExists(String workingDir) throws IOException {
            if (localKeytabDir == null || Files.notExists(localKeytabDir)) {
                Path path = Paths.get(workingDir);
                if (Files.notExists(path)) {
                    Path parent = path.getParent().toRealPath();
                    Path resolvedPath = Paths.get(parent.toString(), path.getFileName().toString());
                    path = Files.createDirectories(resolvedPath);
                }
                localKeytabDir = Files.createTempDirectory(path, "keytabs");
            }
        }

        @Override
        public void run() {
            String principal = securityConfig.getPrincipal();

            Path originalKeytab = Paths.get(securityConfig.getKeytab());
            Set<Path> keytabs = new LinkedHashSet<>();
            keytabs.add(originalKeytab);
            try {
                createLocalKeytabDirIfNotExists(workingDir);
                Files.list(localKeytabDir).forEach(keytabs::add);
                LOG.debug(
                        "Local keytab files stored in {}, current local keytab files: {}",
                        localKeytabDir,
                        keytabs.stream().map(Path::toString).collect(Collectors.joining(",")));
            } catch (IOException e) {
                e.printStackTrace();
            }

            Optional<Path> validKeytabOpt =
                    keytabs.stream()
                            .filter(
                                    kt ->
                                            KerberosUtils.checkKeytabValid(
                                                    principal, kt.toAbsolutePath().toString()))
                            .findFirst();

            if (!validKeytabOpt.isPresent()) {
                LOG.error("No valid keytab found!");
            } else {
                Path validKeytab = validKeytabOpt.get();
                LOG.info("Current valid keytab: {}", validKeytab.toAbsolutePath());
                // try to replace the orignal keytab
                synchronized (UserGroupInformation.class) {
                    try {
                        // double check whether the keytab is still valid
                        if (KerberosUtils.checkKeytabValid(
                                principal, validKeytab.toAbsolutePath().toString())) {
                            Files.move(
                                    validKeytab,
                                    originalKeytab,
                                    StandardCopyOption.REPLACE_EXISTING);
                            // refresh the UGI to use the new keytab
                            UserGroupInformation.getLoginUser().checkTGTAndReloginFromKeytab();
                        }
                    } catch (IOException e) {
                        LOG.error("Failed to re-login with new keytab {}: {}", validKeytab, e);
                    }
                }
            }

            List<Path> downloadedKeytabs = downloadKeytabFromHdfs();
            if (downloadedKeytabs.size() > 0) {
                LOG.info(
                        "Downloaded {} keytab files from {}",
                        downloadedKeytabs.size(),
                        securityConfig.getKeytabUpdatePath());
            }
        }

        private List<Path> downloadKeytabFromHdfs() {
            final List<Path> downloaded = new ArrayList<>();
            org.apache.hadoop.fs.Path srcPath =
                    new org.apache.hadoop.fs.Path(securityConfig.getKeytabUpdatePath());
            try {
                FileSystem fs = srcPath.getFileSystem(hadoopConfig);
                if (!fs.exists(srcPath)) {
                    LOG.warn("The {} does not exist", srcPath);
                    return downloaded;
                }

                List<org.apache.hadoop.fs.Path> keytabFiles =
                        Stream.of(fs.listStatus(srcPath))
                                .filter(FileStatus::isFile)
                                .map(FileStatus::getPath)
                                .collect(Collectors.toList());
                LOG.info("There are {} keytab files found in {}", keytabFiles.size(), srcPath);

                Preconditions.checkNotNull(localKeytabDir);
                keytabFiles.forEach(
                        file -> {
                            try {
                                // TODO: add some logic to skip already downloaded keytab files
                                Path targetFile =
                                        Paths.get(localKeytabDir.toString(), file.getName());
                                download(fs.open(file), targetFile.toString());
                                downloaded.add(targetFile);
                            } catch (IOException e) {
                                LOG.error("Failed to download {}", file);
                            }
                        });
            } catch (IOException e) {
                LOG.error("Failed to list the {}: {}", srcPath, e);
            }
            return downloaded;
        }

        static void download(DataInputStream inputStream, String targetFile) throws IOException {
            File file = new File(targetFile);
            FileUtils.copyInputStreamToFile(inputStream, file);
        }
    }
}
