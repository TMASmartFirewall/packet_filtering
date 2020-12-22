<template>
  <v-app>
    <v-app-bar
      app
      dark
    >
    <h1>Packet Filterting</h1>

      <v-spacer></v-spacer>

      <v-btn
        href="https://github.com/TMASmartFirewall/packet_filtering"
        target="_blank"
        text
      >
        <span class="mr-2">Open Git-Hub</span>
        <v-icon>mdi-open-in-new</v-icon>
      </v-btn>
    </v-app-bar>

    <v-main class="grey">
      <HelloWorld/>
    </v-main>
  </v-app>
</template>

<script>
import HelloWorld from './components/HelloWorld';

export default {
  name: 'App',

  components: {
    HelloWorld,
  },

  data: () => ({
    //
  }),
};
</script>
