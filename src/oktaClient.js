const axios = require('axios');

class OktaClient {
  constructor(domain, apiToken) {
    this.domain = domain;
    this.apiToken = apiToken;
    this.baseUrl = `https://${domain}/api/v1`;

    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `SSWS ${apiToken}`
      }
    });
  }

  async querySystemLog(filter, since = null, limit = 100) {
    try {
      const params = {
        filter: filter,
        limit: limit,
        sortOrder: 'DESCENDING'
      };

      if (since) {
        params.since = since;
      }

      const results = [];
      let url = '/logs';
      let hasMore = true;

      while (hasMore && results.length < limit) {
        const response = await this.client.get(url, {
          params: url === '/logs' ? params : undefined
        });

        results.push(...response.data);

        // Check for pagination link
        const linkHeader = response.headers.link;
        if (linkHeader && linkHeader.includes('rel="next"')) {
          const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
          if (nextMatch) {
            url = nextMatch[1].replace(this.baseUrl, '');
          } else {
            hasMore = false;
          }
        } else {
          hasMore = false;
        }

        // Respect rate limits with small delay
        await this.sleep(100);
      }

      return results.slice(0, limit);
    } catch (error) {
      if (error.response) {
        throw new Error(`Okta API Error: ${error.response.status} - ${error.response.data.errorSummary || error.response.statusText}`);
      } else if (error.request) {
        throw new Error('Network error: Unable to reach Okta API');
      } else {
        throw error;
      }
    }
  }

  async testConnection() {
    try {
      await this.client.get('/logs', { params: { limit: 1 } });
      return true;
    } catch (error) {
      throw new Error(`Connection test failed: ${error.message}`);
    }
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = OktaClient;
