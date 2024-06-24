<script setup>
//import html2pdf from "html2pdf.js"
import pdfMake from "pdfmake/build/pdfmake";
import pdfFonts from "pdfmake/build/vfs_fonts";
pdfMake.vfs = pdfFonts.pdfMake.vfs;
import { ref, onMounted, toRaw } from 'vue';
import { useRoute, /*useRouter*/ } from 'vue-router'
import axios from 'axios';
const route = useRoute();
//const router = useRouter();
const evaluationResults = ref([]);
const ownerId = ref();
const EvaluationDescprition = ref("A continuación se presentan los resultados de la evaluación de usabilidad, utilizando el método de prueba denominado analisis heuristico. Se muestra la tabla de resultados con sus respectivos niveles de criterios de usabilidad");
//const exportValues = ref();
onMounted(() => {
    ownerId.value = route.params.ownerId
    getEvaluationResults();

})

const getEvaluationResults = async () => {
    try {
        const response = await axios.get(`http://127.0.0.1:5000/evaluations/${ownerId.value}`);
        evaluationResults.value = response.data;
        console.log("Informacion del get", evaluationResults.value);
        
        // Llama a la función para generar el PDF con los resultados y la gráfica
        infode();
    } catch (error) {
        console.error("Error al obtener los resultados de la evaluación:", error);
    }
};

const infode = () => {

    const valuesArray = toRaw(evaluationResults.value).map(obj => Object.values(obj));
    let arreglofinal = [['Código', 'Descripción', 'Heuristica Incumplida', 'Criticismo', 'Frecuencia', "Severidad", 'Incidentes']];
    valuesArray.forEach(value => {

        arreglofinal.push([value[5], value[1], value[3], value[0], value[2], value[6], value[4]]);
    }
    );
    
    console.log(arreglofinal);
    var dd = {
        content: [
            { text: 'Tables', style: 'header' },
            EvaluationDescprition.value,
            { text: 'Resultados Evaluacioon', style: 'subheader' },
            'Resultado de la evaluacion',
            {
                style: 'tableExample',
                table: {
                    body: arreglofinal
                }
            }
        ],
        styles: {
            header: {
                fontSize: 18,
                bold: true,
                margin: [0, 0, 0, 10]
            },
            subheader: {
                fontSize: 16,
                bold: true,
                margin: [0, 10, 0, 5]
            },
            tableExample: {
                margin: [0, 5, 0, 15]
            },
            tableHeader: {
                bold: true,
                fontSize: 13,
                color: 'black'
            }
        },
        defaultStyle: {
            // alignment: 'justify'
        }


    }

    

    pdfMake.createPdf(dd).open();

};



const exportPDF = () => {
    infode();
}

</script>

<template>
    <div class="container-fluid">
        <div><button class="btn btn-success" @click="exportPDF()">Descargar PDF</button></div>
        <div class="row">
            <div class="col-12">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">Resultados</h5>
                    </div>
                    <div class="card-body">
                        <p class="card-text">{{ EvaluationDescprition }}</p>
                    </div>
                </div>
                <div class="card mt-3">
                    <div class="card-header">
                        <h6 class="card-title">Evaluaciones</h6>
                    </div>
                    <div class="card-body">
                        <table class="table table-striped table-warning">
                            <thead>
                                <tr>
                                    <th>Código</th>
                                    <th>Descripción</th>
                                    <th>Heuristica Incumplida</th>
                                    <th>Criticismo</th>
                                    <th>Frecuencia</th>
                                    <th>Severidad</th>
                                    <th>Incidentes</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="evaluation in evaluationResults" :key="evaluation.name">
                                    <td>{{ evaluation.name }}</td>
                                    <td>{{ evaluation.description }}</td>
                                    <td>{{ evaluation.hi }}</td>
                                    <td>{{ evaluation.criticism }}</td>
                                    <td>{{ evaluation.frequency }}</td>
                                    <td>{{ evaluation.severity }}</td>
                                    <td>{{ evaluation.incidents }}</td>

                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>