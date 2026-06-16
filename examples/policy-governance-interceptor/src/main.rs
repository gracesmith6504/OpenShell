// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;

use openshell_core::proto::interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
use policy_governance_interceptor::GovernanceInterceptor;
use tonic::transport::Server;

const DEFAULT_ADDR: &str = "127.0.0.1:18098";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_ADDR.to_string())
        .parse()?;
    tracing::info!(%addr, "policy governance interceptor listening");

    let interceptor = GovernanceInterceptor::new()
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    Server::builder()
        .add_service(GatewayInterceptorServer::new(interceptor))
        .serve(addr)
        .await?;

    Ok(())
}
