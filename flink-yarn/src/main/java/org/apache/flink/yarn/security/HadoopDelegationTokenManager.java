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

package org.apache.flink.yarn.security;

import org.apache.flink.annotation.VisibleForTesting;
import org.apache.flink.runtime.security.delegationtokens.HadoopDelegationTokenConfiguration;
import org.apache.flink.runtime.security.delegationtokens.HadoopDelegationTokenProvider;

import org.apache.hadoop.security.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * HadoopDelegationTokenManager is responsible for managing delegation tokens. It can be used to
 * obtain delegation tokens by calling `obtainDelegationTokens` method.
 */
public class HadoopDelegationTokenManager {
    private static final Logger LOG = LoggerFactory.getLogger(HadoopDelegationTokenManager.class);

    private final HadoopDelegationTokenConfiguration hadoopDelegationTokenConf;
    private final List<HadoopDelegationTokenProvider> delegationTokenProviders;

    public HadoopDelegationTokenManager(
            HadoopDelegationTokenConfiguration hadoopDelegationTokenConf) {
        this.hadoopDelegationTokenConf = hadoopDelegationTokenConf;
        delegationTokenProviders = loadProviders();
    }

    /**
     * Obtain delegation tokens using HadoopDelegationProviders, and store them in the give
     * credentials.
     *
     * @param credentials Credentials object where to store the delegation tokens.
     */
    public void obtainDelegationTokens(Credentials credentials) {
        delegationTokenProviders.forEach(
                provider -> {
                    if (provider.delegationTokensRequired()) {
                        provider.obtainDelegationTokens(credentials);
                    } else {
                        LOG.debug(
                                "Service {} does not need to obtain delegation token.",
                                provider.serviceName());
                    }
                });
    }

    private List<HadoopDelegationTokenProvider> loadProviders() {
        ServiceLoader<HadoopDelegationTokenProvider> serviceLoader =
                ServiceLoader.load(HadoopDelegationTokenProvider.class);

        List<HadoopDelegationTokenProvider> providers = new ArrayList<>();

        Iterator<HadoopDelegationTokenProvider> providerIterator = serviceLoader.iterator();
        providerIterator.forEachRemaining(
                provider -> {
                    try {
                        provider.init(hadoopDelegationTokenConf);
                        LOG.debug(
                                "Delegation provider {} loaded and initialized",
                                provider.serviceName());
                    } catch (Throwable throwable) {
                        LOG.info(
                                "Failed to initialize delegation provider {}, exception: {}",
                                provider.serviceName(),
                                throwable);
                    }
                    providers.add(provider);
                });
        return providers;
    }

    @VisibleForTesting
    boolean isProviderLoaded(String serviceName) {
        return delegationTokenProviders.stream()
                .anyMatch(provider -> provider.serviceName().equals(serviceName));
    }
}
