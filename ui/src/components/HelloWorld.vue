<template>
  <v-container>
    <v-row class="text-center">
      <v-col cols="6">
        <v-card elevation="12">
        <div id="chartContainer" style="height: 700px; width: 100%;"></div>
      </v-card>

      </v-col>
      <v-col cols="6">
        <v-simple-table dark>
    <template v-slot:default>
      <thead>
        <tr>
          <th class="text-left">
            Url
          </th>
          <th class="text-left">
            Connections
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="(i,x) in 20"
          :key="i"
        >
          <td>{{ sites[x].label }}</td>
          <td>{{ sites[x].y }}</td>
        </tr>
      </tbody>
    </template>
  </v-simple-table>
      </v-col>
    </v-row>
  </v-container>
</template>

<script>
import CanvasJS from '@/assets/canvasjs.min.js'
import sites from '@/assets/sites.json'

export default {
  name: 'HelloWorld',

  data: () => ({
    data: [{
      type: "bar",
      axisYType: "secondary",
      indexLabel: "{y}",
      dataPoints: [
      ]
    }],
    data2: [{
      type: "pie",
      axisYType: "secondary",
      indexLabel: "{y}",
      dataPoints: [
      ]
    }],
    page: 0,
    sites : []
  }),
  mounted() {
    this.sites = this.parseSites()
    let dades = this.data

    dades[0].dataPoints = this.sites.slice(0,30)
    //do something after mounting vue instance
    const chart = new CanvasJS.Chart("chartContainer", {
      theme: "dark1", // "light1", "light2", "dark1"
      animationEnabled: true,
      exportEnabled: true,
      title: {
        text: "Top 20 Most Visited Sites"
      },
      axisX: {
        margin: 10,
        labelPlacement: "inside",
        tickPlacement: "inside"
      },
      axisY2: {
        title: "Visits",
        titleFontSize: 0,
        includeZero: true,
      },
      data: dades
    });
    chart.render();

  },
  methods: {
    parseSites() {
      let points = []
      sites.forEach((item) => {
        let exists = points.find( candidate => candidate.label === item.question )
        if(!exists)
          points.push({label: item.question, y: 1})
        else
          exists.y += 1
      });

      points.sort((a, b) => {
        let fa = a.y,
        fb = b.y;

        if (fa < fb) {
          return 1;
        }
        if (fa > fb) {
          return -1;
        }
        return 0;
      });
      return points
    }
  }
}
</script>
