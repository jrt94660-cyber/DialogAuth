package com.taho.dialogauth;

import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogBase;
import io.papermc.paper.dialog.DialogInput;
import io.papermc.paper.dialog.DialogType;
import io.papermc.paper.dialog.ActionButton;
import io.papermc.paper.dialog.DialogAction;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.key.Key;
import org.bukkit.Bukkit;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.*;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitTask;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class DialogAuth extends JavaPlugin implements Listener {
    private final Map<UUID, Long> authenticated = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private File usersFile;
    private YamlConfiguration users;
    private long sessionMinutes;
    private int maxAttempts;
    private int minPasswordLength;
    private BukkitTask reminderTask;

    @Override public void onEnable() {
        saveDefaultConfig();
        saveResourceIfMissing();
        loadSettings();
        loadUsers();
        Bukkit.getPluginManager().registerEvents(this, this);
        getCommand("dialogauth").setExecutor((sender, command, label, args) -> {
            if (args.length == 1 && args[0].equalsIgnoreCase("reload")) {
                if (!sender.hasPermission("dialogauth.admin")) { sender.sendMessage("§cNo permission."); return true; }
                reloadConfig(); loadSettings(); sender.sendMessage("§aDialogAuth configuration reloaded."); return true;
            }
            if (args.length == 2 && args[0].equalsIgnoreCase("unregister")) {
                if (!sender.hasPermission("dialogauth.admin")) { sender.sendMessage("§cNo permission."); return true; }
                String name = args[1];
                if (!users.contains(name.toLowerCase())) { sender.sendMessage("§cNo registered account found for " + name + "."); return true; }
                users.set(name.toLowerCase(), null); saveUsers();
                sender.sendMessage("§aRemoved DialogAuth account for " + name + "."); return true;
            }
            if (args.length == 1 && args[0].equalsIgnoreCase("login") && sender instanceof Player player) {
                showAuthDialog(player); return true;
            }
            sender.sendMessage("§e/dialogauth reload §7- reload config");
            sender.sendMessage("§e/dialogauth unregister <player> §7- remove a registration");
            sender.sendMessage("§e/dialogauth login §7- reopen your authentication screen");
            return true;
        });
        reminderTask = Bukkit.getScheduler().runTaskTimer(this, () -> {
            for (Player player : Bukkit.getOnlinePlayers()) if (!isAuthenticated(player)) showAuthDialog(player);
        }, 20L, 20L);
        getLogger().info("DialogAuth enabled. Native dialogs require a compatible Paper server and Java client.");
    }

    @Override public void onDisable() {
        if (reminderTask != null) reminderTask.cancel();
        saveUsers();
    }

    private void saveResourceIfMissing() {
        File f = new File(getDataFolder(), "config.yml");
        if (!f.exists()) saveDefaultConfig();
    }
    private void loadSettings() {
        sessionMinutes = Math.max(1, getConfig().getLong("session-expiry-minutes", 30));
        maxAttempts = Math.max(1, getConfig().getInt("security.max-login-attempts", 5));
        minPasswordLength = Math.max(6, getConfig().getInt("security.min-password-length", 6));
    }
    private void loadUsers() {
        if (!getDataFolder().exists()) getDataFolder().mkdirs();
        usersFile = new File(getDataFolder(), "users.yml");
        users = YamlConfiguration.loadConfiguration(usersFile);
    }
    private synchronized void saveUsers() {
        try { users.save(usersFile); } catch (IOException e) { getLogger().severe("Could not save users.yml: " + e.getMessage()); }
    }

    @EventHandler public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        authenticated.remove(player.getUniqueId());
        attempts.remove(player.getUniqueId());
        Bukkit.getScheduler().runTaskLater(this, () -> {
            if (player.isOnline() && !isAuthenticated(player)) showAuthDialog(player);
        }, 5L);
    }
    @EventHandler public void onQuit(PlayerQuitEvent event) {
        UUID id = event.getPlayer().getUniqueId();
        Long lastAuth = authenticated.remove(id);
        if (lastAuth != null) getConfig().set("sessions." + id, System.currentTimeMillis());
        saveConfig();
        attempts.remove(id);
    }

    private boolean isAuthenticated(Player player) {
        Long time = authenticated.get(player.getUniqueId());
        return time != null && System.currentTimeMillis() - time < sessionMinutes * 60_000L;
    }
    private void markAuthenticated(Player player) {
        authenticated.put(player.getUniqueId(), System.currentTimeMillis());
        getConfig().set("sessions." + player.getUniqueId(), System.currentTimeMillis());
        saveConfig();
        player.closeDialog();
        player.sendMessage("§aYou are authenticated. Welcome!");
    }

    private void showAuthDialog(Player player) {
        if (!player.isOnline() || isAuthenticated(player)) return;
        String key = player.getName().toLowerCase();
        boolean registered = users.contains(key);
        DialogInput passwordInput = DialogInput.text("password", Component.text(registered ? "Password" : "Create a password"))
                .label(Component.text(registered ? "Enter your password" : "Choose a password"))
                .width(300)
                .build();
        Dialog dialog = Dialog.create(builder -> builder.empty()
                .base(DialogBase.builder(Component.text(registered ? "§6Login" : "§6Register"))
                        .canCloseWithEscape(false)
                        .body(java.util.List.of(net.kyori.adventure.text.event.HoverEvent.showText(Component.text("Authenticate to play")) == null
                                ? null : io.papermc.paper.dialog.DialogBody.plainMessage(Component.text(registered
                                ? "Enter the password for your account." : "Create a password to protect your account."))))
                        .inputs(java.util.List.of(passwordInput))
                        .build())
                .type(DialogType.multiAction(java.util.List.of(
                        ActionButton.builder(Component.text(registered ? "Login" : "Register"))
                                .action(DialogAction.customClick((view, audience) -> {
                                    if (!(audience instanceof Player p) || !p.isOnline()) return;
                                    String password = view.getText("password");
                                    if (password == null || password.isBlank()) { p.sendMessage("§cPlease enter a password."); showAuthDialog(p); return; }
                                    if (registered) handleLogin(p, key, password);
                                    else handleRegister(p, key, password);
                                }))
                                .build()
                )))
        );
        player.showDialog(dialog);
    }

    private void handleRegister(Player player, String key, String password) {
        if (users.contains(key)) { showAuthDialog(player); return; }
        if (password.length() < minPasswordLength) {
            player.sendMessage("§cPassword must be at least " + minPasswordLength + " characters.");
            showAuthDialog(player); return;
        }
        users.set(key + ".uuid", player.getUniqueId().toString());
        users.set(key + ".password", hashPassword(password));
        users.set(key + ".created", System.currentTimeMillis());
        saveUsers();
        markAuthenticated(player);
    }

    private void handleLogin(Player player, String key, String password) {
        String storedUuid = users.getString(key + ".uuid", "");
        if (!storedUuid.equals(player.getUniqueId().toString())) {
            player.kick(Component.text("This username is registered to a different offline UUID."));
            return;
        }
        String expected = users.getString(key + ".password", "");
        if (!MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), hashPassword(password).getBytes(StandardCharsets.UTF_8))) {
            int count = attempts.merge(player.getUniqueId(), 1, Integer::sum);
            if (count >= maxAttempts) { player.kick(Component.text("Too many incorrect password attempts.")); return; }
            player.sendMessage("§cIncorrect password. Attempts: " + count + "/" + maxAttempts);
            showAuthDialog(player); return;
        }
        markAuthenticated(player);
    }

    private String hashPassword(String password) {
        try {
            byte[] salt = getConfig().getString("security.hash-salt", "DialogAuth-change-this-salt").getBytes(StandardCharsets.UTF_8);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(salt);
            return Base64.getEncoder().encodeToString(digest.digest(password.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }

    @EventHandler public void onMove(PlayerMoveEvent event) {
        if (!isAuthenticated(event.getPlayer())) {
            if (event.getTo() != null && (event.getFrom().getX() != event.getTo().getX()
                    || event.getFrom().getY() != event.getTo().getY() || event.getFrom().getZ() != event.getTo().getZ())) event.setCancelled(true);
        }
    }
    @EventHandler public void onCommand(PlayerCommandPreprocessEvent event) {
        if (!isAuthenticated(event.getPlayer()) && !event.getMessage().equalsIgnoreCase("/dialogauth login")) event.setCancelled(true);
    }
    @EventHandler public void onChat(AsyncPlayerChatEvent event) { if (!isAuthenticated(event.getPlayer())) event.setCancelled(true); }
    @EventHandler public void onInteract(PlayerInteractEvent event) { if (!isAuthenticated(event.getPlayer())) event.setCancelled(true); }
    @EventHandler public void onDrop(PlayerDropItemEvent event) { if (!isAuthenticated(event.getPlayer())) event.setCancelled(true); }
    @EventHandler public void onPickup(PlayerAttemptPickupItemEvent event) { if (!isAuthenticated(event.getPlayer())) event.setCancelled(true); }
}