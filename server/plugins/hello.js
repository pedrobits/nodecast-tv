/**
 * Example plugin demonstrating async initialization and service access
 * This plugin registers a test route at /api/hello
 */
module.exports = async function (app, services) {
    console.log("Plugin 'Hello' activated!");

    // Example: Access loaded services
    if (services.syncService) {
        console.log("   - syncService is available");
    }

    // Simulate async initialization (e.g., database connection, API setup)
    await new Promise(resolve => setTimeout(resolve, 100));

    // Register a test route accessible at http://localhost:3000/api/hello
    app.get('/api/hello', (req, res) => {
        res.json({
            message: "The plugin system is working!",
            availableServices: Object.keys(services)
        });
    });

    console.log("   - Registered route: GET /api/hello");
};